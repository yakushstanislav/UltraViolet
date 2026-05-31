// Package recovery houses periodic janitorial jobs that keep the scan queue
// consistent across worker restarts.
package recovery

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
)

// StaleRunningJob fails RUNNING scans whose started_at is older than maxAge.
type StaleRunningJob struct {
	scanRepository scan.Repository
	maxAge         time.Duration
	logger         *zap.SugaredLogger
}

// NewStaleRunningJob builds the stale-running janitor.
func NewStaleRunningJob(scanRepository scan.Repository, maxAge time.Duration, logger *zap.SugaredLogger) *StaleRunningJob {
	return &StaleRunningJob{
		scanRepository: scanRepository,
		maxAge:         maxAge,
		logger:         logger,
	}
}

// Name implements worker.Job.
func (j *StaleRunningJob) Name() string { return "stale-running" }

// Tick implements worker.Job.
func (j *StaleRunningJob) Tick(ctx context.Context) (bool, error) {
	recovered, err := j.scanRepository.RecoverStaleRunning(ctx, j.maxAge)
	if err != nil {
		return false, fmt.Errorf("can't recover stale running scans: %w", err)
	}

	if recovered > 0 {
		j.logger.Warnw("Recovered stale running scans", zap.Uint64("count", recovered))
	}

	return false, nil
}

// AbandonedCancelJob finalises RUNNING scans whose cancellation was
// requested but never observed by a worker.
type AbandonedCancelJob struct {
	scanRepository scan.Repository
	logger         *zap.SugaredLogger
}

// NewAbandonedCancelJob builds the abandoned-cancellation janitor.
func NewAbandonedCancelJob(scanRepository scan.Repository, logger *zap.SugaredLogger) *AbandonedCancelJob {
	return &AbandonedCancelJob{scanRepository: scanRepository, logger: logger}
}

// Name implements worker.Job.
func (j *AbandonedCancelJob) Name() string { return "abandoned-cancel" }

// Tick implements worker.Job.
func (j *AbandonedCancelJob) Tick(ctx context.Context) (bool, error) {
	finalized, err := j.scanRepository.MarkAbandonedCanceled(ctx)
	if err != nil {
		return false, fmt.Errorf("can't mark abandoned cancellations: %w", err)
	}

	if finalized > 0 {
		j.logger.Infow("Finalized abandoned cancellations", zap.Uint64("count", finalized))
	}

	return false, nil
}
