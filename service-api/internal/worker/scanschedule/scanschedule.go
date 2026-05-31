// Package scanschedule fires due recurring scan schedules.
package scanschedule

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	scanscheduleRepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scanschedule"
	scanschedulesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scanschedule"
)

// Config controls the worker cadence.
type Config struct {
	Enabled  bool          `env:"SCAN_SCHEDULE_ENABLED"  env-default:"true"`
	Interval time.Duration `env:"SCAN_SCHEDULE_INTERVAL" env-default:"60s"`
	Batch    int           `env:"SCAN_SCHEDULE_BATCH"    env-default:"10"`
}

// Job polls due schedules and enqueues scan instances.
type Job struct {
	cfg        Config
	repository scanscheduleRepository.Repository
	service    *scanschedulesvc.Service
	logger     *zap.SugaredLogger
}

// New builds a Job.
func New(
	cfg Config,
	repository scanscheduleRepository.Repository,
	service *scanschedulesvc.Service,
	logger *zap.SugaredLogger,
) *Job {
	return &Job{
		cfg:        cfg,
		repository: repository,
		service:    service,
		logger:     logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "scan_schedule" }

// Tick implements worker.Job.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if !j.cfg.Enabled {
		return false, nil
	}

	batch := j.cfg.Batch
	if batch <= 0 {
		batch = 10
	}

	now := time.Now().UTC()

	due, err := j.repository.DueLocked(ctx, now, batch)
	if err != nil {
		return false, fmt.Errorf("can't list due scan schedules: %w", err)
	}

	if len(due) == 0 {
		return false, nil
	}

	for _, schedule := range due {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}

		response, err := j.service.FireScan(ctx, schedule)
		if err != nil {
			if resetErr := j.repository.ScheduleDue(ctx, schedule.ID, now); resetErr != nil {
				j.logger.Warnw("Can't reschedule failed scan claim",
					zap.Uint64("schedule_id", schedule.ID),
					zap.Error(resetErr),
				)
			}

			j.logger.Warnw("Can't fire scan schedule",
				zap.Uint64("schedule_id", schedule.ID),
				zap.Error(err),
			)

			continue
		}

		if len(response.ScanIDs) == 0 {
			continue
		}

		if err := j.service.RecordClaimedRun(ctx, schedule.ID, response.ScanIDs[0]); err != nil {
			j.logger.Warnw("Can't record scan schedule run",
				zap.Uint64("schedule_id", schedule.ID),
				zap.Error(err),
			)
		}
	}

	return true, nil
}
