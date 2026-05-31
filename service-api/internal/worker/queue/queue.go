// Package queue consumes the uv_scan job queue and drives the scanner pipeline.
package queue

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmode"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanprofile"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/targetstrategy"
	deltarepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/delta"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/scanner"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/cancel"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/pause"
)

// cursorFlushInterval throttles disk writes for the resume cursor. The
// in-memory cursor is updated on every IP emission; the worker only
// persists it this often plus on pause/finalize.
const cursorFlushInterval = 2 * time.Second

// Job claims and runs one pending scan per Tick. Returns didWork=true whenever
// a job was processed (success or failure).
type Job struct {
	scanRepository  scan.Repository
	deltaRepository deltarepository.Repository
	pipeline        *scanner.Pipeline
	cancelLn        *cancel.Listener
	pauseLn         *pause.Listener
	logger          *zap.SugaredLogger
}

// New builds a Job.
func New(
	scanRepository scan.Repository,
	deltaRepository deltarepository.Repository,
	pipeline *scanner.Pipeline,
	cancelLn *cancel.Listener,
	pauseLn *pause.Listener,
	logger *zap.SugaredLogger,
) *Job {
	return &Job{
		scanRepository:  scanRepository,
		deltaRepository: deltaRepository,
		pipeline:        pipeline,
		cancelLn:        cancelLn,
		pauseLn:         pauseLn,
		logger:          logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "scan-queue" }

// Tick implements worker.Job. It returns errors.Is(err, scan.ErrNoPendingScan)
// as a soft signal to the runner (no work, no error).
func (j *Job) Tick(ctx context.Context) (bool, error) {
	scanJob, err := j.scanRepository.Claim(ctx)
	if errors.Is(err, scan.ErrNoPendingScan) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("can't claim pending scan: %w", err)
	}

	if err := j.runScan(ctx, scanJob); err != nil {
		return true, err
	}

	return true, nil
}

func (j *Job) runScan(ctx context.Context, scanJob *scan.Scan) (retErr error) {
	start := time.Now()

	scanmetrics.ScansInFlight.Inc()

	defer scanmetrics.ScansInFlight.Dec()
	defer func() {
		outcome := "ok"
		if retErr != nil {
			outcome = "error"
		}

		scanmetrics.ScanDurationSeconds.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
	}()

	cidr := ""
	if scanJob.CIDR.Valid {
		cidr = scanJob.CIDR.String
	}

	j.logger.Infow("Claimed scan",
		zap.Uint64("id", scanJob.ID),
		zap.String("cidr", cidr),
		zap.String("target_strategy", scanJob.TargetStrategy),
		zap.Int("ports_count", len(scanJob.Ports)),
	)

	ports := make([]uint16, 0, len(scanJob.Ports))

	for _, port := range scanJob.Ports {
		if port < 1 || port > 65535 {
			return j.failScan(ctx, scanJob.ID, fmt.Errorf("invalid port %d", port), nil)
		}

		ports = append(ports, uint16(port))
	}

	mode, modeErr := scanmode.Parse(scanJob.Mode)
	if modeErr != nil {
		j.logger.Warnw("Invalid scan mode in database, falling back to slow mode",
			zap.Uint64("scan_id", scanJob.ID),
			zap.String("mode", scanJob.Mode),
			zap.Error(modeErr),
		)

		mode = scanmode.Slow
	}

	profile, profileErr := scanprofile.Parse(scanJob.SlowProfile)
	if profileErr != nil {
		j.logger.Warnw("Invalid slow profile in database, falling back to stealth",
			zap.Uint64("scan_id", scanJob.ID),
			zap.String("slow_profile", scanJob.SlowProfile),
			zap.Error(profileErr),
		)

		profile = scanprofile.Stealth
	}

	strategy, strategyErr := targetstrategy.Parse(scanJob.TargetStrategy)
	if strategyErr != nil {
		j.logger.Warnw("Invalid target strategy in database, falling back to sequential",
			zap.Uint64("scan_id", scanJob.ID),
			zap.String("target_strategy", scanJob.TargetStrategy),
			zap.Error(strategyErr),
		)

		strategy = targetstrategy.Sequential
	}

	var limit uint64

	if scanJob.HostLimit.Valid && scanJob.HostLimit.Int64 > 0 {
		limit = uint64(scanJob.HostLimit.Int64)
	}

	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()

	cancelCh, cancelStop := j.cancelLn.Subscribe(scanCtx, scanJob.ID)

	defer cancelStop()

	pauseCh, pauseStop := j.pauseLn.Subscribe(scanCtx, scanJob.ID)

	defer pauseStop()

	go j.watchSignals(scanCtx, cancelCh, pauseCh, scanJob.ID, cancelScan)

	var latestCursor atomic.Pointer[string]

	cursorUpdate := func(_ context.Context, cursor string) error {
		latestCursor.Store(&cursor)

		return nil
	}

	flusherCtx, stopFlusher := context.WithCancel(scanCtx)
	flusherDone := make(chan struct{})

	go j.flushCursor(flusherCtx, scanJob.ID, &latestCursor, flusherDone)

	stats, runErr := j.pipeline.Run(scanCtx, scanner.Request{
		CIDR:           cidr,
		AllowedCIDRs:   j.pipeline.AllowedCIDRs(),
		Country:        scanJob.Country.String,
		TargetStrategy: strategy,
		Limit:          limit,
		Ports:          ports,
		Mode:           mode,
		SlowProfile:    profile,
		Progress: func(ctx context.Context, stats scanner.Stats) error {
			return j.scanRepository.UpdateStats(ctx, scanJob.ID, stats.Map())
		},
		ResumeCursor: scanJob.ProgressCursor,
		CursorUpdate: cursorUpdate,
		InitialStats: seedStatsFromMap(scanJob.Stats),
	})

	stopFlusher()
	<-flusherDone

	j.persistFinalCursor(ctx, scanJob.ID, &latestCursor)

	return j.finalize(ctx, scanJob.ID, stats, runErr)
}

// flushCursor periodically persists the latest in-memory cursor pointer to
// the DB so that a crash between flushes loses at most cursorFlushInterval
// worth of progress.
func (j *Job) flushCursor(
	ctx context.Context,
	scanID uint64,
	latest *atomic.Pointer[string],
	done chan<- struct{},
) {
	defer close(done)

	ticker := time.NewTicker(cursorFlushInterval)
	defer ticker.Stop()

	var lastWritten string

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		ptr := latest.Load()
		if ptr == nil {
			continue
		}

		current := *ptr
		if current == lastWritten {
			continue
		}

		if err := j.scanRepository.UpdateProgressCursor(ctx, scanID, current); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			j.logger.Debugw("Can't flush progress cursor",
				zap.Uint64("scan_id", scanID),
				zap.Error(err),
			)

			continue
		}

		lastWritten = current
	}
}

// persistFinalCursor writes the most recently emitted cursor under a fresh
// context so the value survives ctx cancellation (e.g. SIGINT during a scan).
func (j *Job) persistFinalCursor(parent context.Context, scanID uint64, latest *atomic.Pointer[string]) {
	ptr := latest.Load()
	if ptr == nil {
		return
	}

	ctx := parent
	if ctx.Err() != nil {
		ctx = context.Background()
	}

	if err := j.scanRepository.UpdateProgressCursor(ctx, scanID, *ptr); err != nil {
		j.logger.Warnw("Can't persist final progress cursor",
			zap.Uint64("scan_id", scanID),
			zap.Error(err),
		)
	}
}

// seedStatsFromMap rebuilds the typed stats struct from the JSON map stored
// in uv_scan.stats, so a resumed scan keeps climbing in the UI instead of
// starting from zero. Missing or wrong-typed keys default to 0.
func seedStatsFromMap(raw map[string]any) scanner.Stats {
	return scanner.Stats{
		OpenPorts:      uint64FromAny(raw["open_ports"]),
		Probed:         uint64FromAny(raw["probed"]),
		Stored:         uint64FromAny(raw["stored"]),
		Errors:         uint64FromAny(raw["errors"]),
		EmittedTargets: uint64FromAny(raw["emitted_targets"]),
	}
}

func uint64FromAny(v any) uint64 {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0
		}

		return uint64(n)
	case int64:
		if n < 0 {
			return 0
		}

		return uint64(n)
	case uint64:
		return n
	default:
		return 0
	}
}

// finalize records the terminal state for a scan run.
//
// The precedence rules are:
//  1. cancel_requested → CANCELED (operator override always wins).
//  2. pause_requested  → PAUSED, auto_resume=false (explicit user pause).
//  3. runErr == context.Canceled with no flags set → PAUSED, auto_resume=true.
//     This covers two cases: worker shutdown (parent ctx done) and a pause
//     request that was retracted after the pipeline was already cancelled.
//     In both cases preserve the work by making the scan auto-resumable.
//  4. otherwise: failScan on runErr, DONE on success.
func (j *Job) finalize(parent context.Context, scanID uint64, stats scanner.Stats, runErr error) error {
	statsCtx := parent
	if statsCtx.Err() != nil {
		statsCtx = context.Background()
	}

	if err := j.scanRepository.UpdateStats(statsCtx, scanID, stats.Map()); err != nil {
		j.logger.Warnw("Can't update final scan stats", zap.Error(err))
	}

	parentDone := parent.Err() != nil

	cancelRequested, lookupErr := j.scanRepository.IsCancelRequested(statsCtx, scanID)
	if lookupErr != nil {
		j.logger.Warnw("Can't read cancellation status",
			zap.Uint64("scan_id", scanID),
			zap.Error(lookupErr),
		)
	}

	if cancelRequested {
		if err := j.scanRepository.UpdateStatus(statsCtx, scanID, scan.StatusCanceled, scan.CancelReasonByUser); err != nil {
			j.logger.Warnw("Can't mark scan as canceled",
				zap.Uint64("scan_id", scanID),
				zap.Error(err),
			)

			if parentDone {
				return parent.Err()
			}

			return fmt.Errorf("can't mark scan as canceled: %w", err)
		}

		j.logger.Infow("Scan canceled",
			zap.Uint64("id", scanID),
			zap.Bool("worker_shutdown", parentDone),
			zap.Any("stats", stats.Map()),
		)

		if parentDone {
			return parent.Err()
		}

		return nil
	}

	pauseRequested, pauseLookupErr := j.scanRepository.IsPauseRequested(statsCtx, scanID)
	if pauseLookupErr != nil {
		j.logger.Warnw("Can't read pause status",
			zap.Uint64("scan_id", scanID),
			zap.Error(pauseLookupErr),
		)
	}

	if pauseRequested {
		if err := j.scanRepository.MarkPaused(statsCtx, scanID, scan.PauseReasonByUser, false); err != nil {
			j.logger.Warnw("Can't mark scan as paused",
				zap.Uint64("scan_id", scanID),
				zap.Error(err),
			)

			if parentDone {
				return parent.Err()
			}

			return fmt.Errorf("can't mark scan as paused: %w", err)
		}

		j.logger.Infow("Scan paused",
			zap.Uint64("id", scanID),
			zap.Bool("worker_shutdown", parentDone),
			zap.Any("stats", stats.Map()),
		)

		if parentDone {
			return parent.Err()
		}

		return nil
	}

	if errors.Is(runErr, context.Canceled) {
		if err := j.scanRepository.MarkPaused(statsCtx, scanID, scan.PauseReasonInterrupted, true); err != nil {
			j.logger.Warnw("Can't mark interrupted scan as paused",
				zap.Uint64("scan_id", scanID),
				zap.Error(err),
			)
		} else {
			j.logger.Infow("Scan interrupted, paused for resume",
				zap.Uint64("id", scanID),
				zap.Bool("worker_shutdown", parentDone),
				zap.Any("stats", stats.Map()),
			)
		}

		if parentDone {
			return runErr
		}

		return nil
	}

	if runErr != nil {
		return j.failScan(statsCtx, scanID, runErr, stats.Map())
	}

	if err := j.scanRepository.UpdateStatus(statsCtx, scanID, scan.StatusDone, ""); err != nil {
		return fmt.Errorf("can't mark scan as done: %w", err)
	}

	if err := j.deltaRepository.BuildAndStore(statsCtx, scanID); err != nil {
		j.logger.Warnw("Can't build scan delta",
			zap.Uint64("scan_id", scanID),
			zap.Error(err),
		)
	}

	j.logger.Infow("Scan finished",
		zap.Uint64("id", scanID),
		zap.Any("stats", stats.Map()),
	)

	return nil
}

// watchSignals stops the scan as soon as cancellation or pause is requested,
// or when the worker context is cancelled.
func (j *Job) watchSignals(
	ctx context.Context,
	cancelSignal <-chan struct{},
	pauseSignal <-chan struct{},
	scanID uint64,
	cancelScan context.CancelFunc,
) {
	select {
	case <-ctx.Done():
		return
	case _, ok := <-cancelSignal:
		if !ok {
			return
		}

		j.logger.Infow("Cancellation detected, stopping scan",
			zap.Uint64("scan_id", scanID),
		)

		cancelScan()
	case _, ok := <-pauseSignal:
		if !ok {
			return
		}

		j.logger.Infow("Pause detected, stopping scan",
			zap.Uint64("scan_id", scanID),
		)

		cancelScan()
	}
}

func (j *Job) failScan(ctx context.Context, id uint64, err error, stats map[string]any) error {
	scanmetrics.ScanErrorsTotal.WithLabelValues("pipeline").Inc()

	if updateErr := j.scanRepository.UpdateStatus(ctx, id, scan.StatusFailed, err.Error()); updateErr != nil {
		return fmt.Errorf("can't mark scan as failed: %w", updateErr)
	}

	j.logger.Warnw("Scan failed",
		zap.Uint64("id", id),
		zap.Error(err),
		zap.Any("stats", stats),
	)

	return nil
}
