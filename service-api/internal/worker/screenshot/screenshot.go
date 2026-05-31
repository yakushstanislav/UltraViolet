// Package screenshot is the background worker that renders HTTP service
// thumbnails through the headless-Chromium service. It claims pending jobs
// from uv_http_screenshot_job, drives the per-target render, and stores the
// JPEG in uv_http_screenshot.
package screenshot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/screenshotmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpscreenshot"
	screenshotsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/screenshot"
)

const (
	defaultBatch      = 8
	maxAttemptsBudget = 3
	depthSampleEvery  = 30 * time.Second
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Config tunes the worker.
type Config struct {
	Batch int `env:"SCREENSHOT_WORKER_BATCH" env-default:"8"`
}

// Job is the worker.Job implementation.
type Job struct {
	pool                     *pgxpool.Pool
	httpScreenshotRepository httpscreenshot.Repository
	screenshotService        *screenshotsvc.Service
	cfg                      Config
	logger                   *zap.SugaredLogger

	depthMu     sync.Mutex
	lastDepthAt time.Time
}

// New builds a Job.
func New(
	pool *pgxpool.Pool,
	httpScreenshotRepository httpscreenshot.Repository,
	screenshotService *screenshotsvc.Service,
	cfg Config,
	logger *zap.SugaredLogger,
) *Job {
	if cfg.Batch <= 0 {
		cfg.Batch = defaultBatch
	}

	return &Job{
		pool:                     pool,
		httpScreenshotRepository: httpScreenshotRepository,
		screenshotService:        screenshotService,
		cfg:                      cfg,
		logger:                   logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "screenshot" }

// Tick implements worker.Job. Returns didWork=true when at least one job was
// claimed so the worker runner spins immediately for the next batch.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if j.screenshotService == nil || !j.screenshotService.Config.Enabled {
		return false, nil
	}

	j.sampleQueueDepth(ctx)

	jobs, err := j.httpScreenshotRepository.ClaimPending(ctx, j.cfg.Batch)
	if err != nil {
		return false, fmt.Errorf("can't claim screenshot jobs: %w", err)
	}

	if len(jobs) == 0 {
		return false, nil
	}

	limit := j.screenshotService.Config.MaxConcurrent
	if limit <= 0 {
		limit = 1
	}

	concurrency := make(chan struct{}, limit)

	var wg sync.WaitGroup

	for _, job := range jobs {
		wg.Add(1)

		go func(job httpscreenshot.Job) {
			defer wg.Done()

			concurrency <- struct{}{}

			defer func() { <-concurrency }()

			j.processOne(ctx, job)
		}(job)
	}

	wg.Wait()

	return true, nil
}

func (j *Job) processOne(ctx context.Context, job httpscreenshot.Job) {
	defer func() {
		if r := recover(); r != nil {
			j.logger.Errorw("Screenshot render panicked",
				zap.Uint64("service_id", job.ServiceID),
				zap.Any("panic", r),
			)
			j.recordFailure(ctx, job, "panic", fmt.Errorf("renderer panicked: %v", r))
		}
	}()

	target, err := j.loadTarget(ctx, job.ServiceID)
	if err != nil {
		j.recordFailure(ctx, job, "lookup", err)

		return
	}

	if target == nil {
		// Service vanished between enqueue and claim — drop the job silently.
		_ = j.httpScreenshotRepository.DeleteJob(ctx, job.ServiceID)

		return
	}

	url := target.url()
	if url == "" {
		j.recordFailure(ctx, job, "render_error", errors.New("non-HTTP service skipped"))
		// Non-HTTP services can never produce a screenshot; bury terminally.
		_ = j.httpScreenshotRepository.MarkFailed(ctx, job.ServiceID, "non-http service", true)

		return
	}

	release, err := j.screenshotService.Gate.Acquire(ctx)
	if err != nil {
		// ctx canceled — reset the job so another tick can pick it up.
		_ = j.httpScreenshotRepository.MarkFailed(ctx, job.ServiceID, "ctx canceled before slot", false)

		return
	}

	defer release()

	start := time.Now()

	result, err := j.screenshotService.Capture(ctx, url)
	if err != nil {
		outcome := classifyCaptureError(err)
		j.recordFailure(ctx, job, outcome, err)

		terminal := job.Attempts >= maxAttemptsBudget
		_ = j.httpScreenshotRepository.MarkFailed(ctx, job.ServiceID, err.Error(), terminal)

		return
	}

	screenshotmetrics.AttemptsTotal.WithLabelValues("success").Inc()
	screenshotmetrics.DurationSeconds.Observe(time.Since(start).Seconds())
	screenshotmetrics.SizeBytes.Observe(float64(len(result.JPEG)))

	if err := j.httpScreenshotRepository.Upsert(ctx, &httpscreenshot.Screenshot{
		ServiceID:       job.ServiceID,
		BodySHA256:      target.BodySHA256,
		Thumbnail:       result.JPEG,
		ThumbnailWidth:  result.Width,
		ThumbnailHeight: result.Height,
		RenderMS:        int(result.Duration / time.Millisecond),
	}); err != nil {
		j.logger.Warnw("Can't store HTTP screenshot",
			zap.Uint64("service_id", job.ServiceID),
			zap.Error(err),
		)

		_ = j.httpScreenshotRepository.MarkFailed(ctx, job.ServiceID, err.Error(), false)

		return
	}

	if err := j.httpScreenshotRepository.DeleteJob(ctx, job.ServiceID); err != nil {
		j.logger.Warnw("Can't delete completed screenshot job",
			zap.Uint64("service_id", job.ServiceID),
			zap.Error(err),
		)
	}
}

type renderTarget struct {
	ServiceID  uint64
	IP         string
	Port       uint16
	HasTLS     bool
	BodySHA256 sql.NullString
}

func (t *renderTarget) url() string {
	if t == nil {
		return ""
	}

	scheme := "http"
	if t.HasTLS {
		scheme = "https"
	}

	hostport := net.JoinHostPort(t.IP, strconv.Itoa(int(t.Port)))

	return scheme + "://" + hostport + "/"
}

// loadTarget pulls the columns needed to build the navigation URL. Returns
// (nil, nil) when the service or HTTP response was deleted between enqueue
// and claim.
func (j *Job) loadTarget(ctx context.Context, serviceID uint64) (*renderTarget, error) {
	query, args, err := sq.Select(
		"s.id",
		"host(h.ip)",
		"s.port",
		"r.body_sha256",
		"(tc.service_id IS NOT NULL) AS has_tls",
	).
		From("uv_service AS s").
		Join("uv_host AS h ON h.id = s.host_id").
		Join("uv_http_response AS r ON r.service_id = s.id").
		LeftJoin("uv_tls_certificate AS tc ON tc.service_id = s.id").
		Where(squirrel.Eq{"s.id": serviceID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build target lookup query: %w", err)
	}

	var target renderTarget

	if err := j.pool.QueryRow(ctx, query, args...).Scan(
		&target.ServiceID,
		&target.IP,
		&target.Port,
		&target.BodySHA256,
		&target.HasTLS,
	); err != nil {
		if errors.Is(err, pgkit.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("can't load target service %d: %w", serviceID, pgkit.Handle(err))
	}

	return &target, nil
}

func (j *Job) recordFailure(ctx context.Context, job httpscreenshot.Job, outcome string, err error) {
	screenshotmetrics.AttemptsTotal.WithLabelValues(outcome).Inc()

	if errors.Is(err, context.Canceled) {
		return
	}

	if j.logger != nil {
		j.logger.Warnw("Screenshot render failed",
			zap.Uint64("service_id", job.ServiceID),
			zap.Int("attempt", job.Attempts),
			zap.String("outcome", outcome),
			zap.Error(err),
		)
	}

	_ = ctx
}

func classifyCaptureError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, screenshotsvc.ErrDisabled):
		return "disabled"
	default:
		// Network errors reaching the Chromium debugger surface as wrapped
		// dial/read errors; bucket everything non-timeout as render_error
		// rather than guessing transport-vs-protocol.
		return "render_error"
	}
}

// sampleQueueDepth publishes job counts at most every depthSampleEvery so the
// worker doesn't hammer the table on every tick.
func (j *Job) sampleQueueDepth(ctx context.Context) {
	j.depthMu.Lock()

	if time.Since(j.lastDepthAt) < depthSampleEvery {
		j.depthMu.Unlock()

		return
	}

	j.lastDepthAt = time.Now()
	j.depthMu.Unlock()

	depth, err := j.httpScreenshotRepository.QueueDepth(ctx)
	if err != nil {
		if j.logger != nil {
			j.logger.Debugw("Can't sample screenshot queue depth", zap.Error(err))
		}

		return
	}

	for _, status := range []string{httpscreenshot.JobStatusPending, httpscreenshot.JobStatusRunning, httpscreenshot.JobStatusFailed} {
		screenshotmetrics.QueueDepth.WithLabelValues(status).Set(float64(depth[status]))
	}
}
