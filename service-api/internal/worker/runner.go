package worker

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
)

// Runner drives a set of Jobs on a fixed cadence and short-circuits the idle
// sleep whenever any job reports work was done.
type Runner struct {
	interval time.Duration
	jobs     []Job
	logger   *zap.SugaredLogger
}

// NewRunner builds a Runner.
func NewRunner(interval time.Duration, logger *zap.SugaredLogger, jobs ...Job) *Runner {
	return &Runner{
		interval: interval,
		jobs:     jobs,
		logger:   logger,
	}
}

// Run executes the worker loop until ctx is canceled.
func (r *Runner) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		if ctx.Err() != nil {
			return nil
		}

		didWork := r.tickAll(ctx)
		if ctx.Err() != nil {
			return nil
		}

		if didWork {
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (r *Runner) tickAll(ctx context.Context) bool {
	didWork := false

	for _, job := range r.jobs {
		if ctx.Err() != nil {
			return didWork
		}

		if r.runOne(ctx, job) {
			didWork = true
		}
	}

	return didWork
}

// runOne wraps a single job tick in panic recovery so one malformed row in
// any of the workers can't crash the entire runner goroutine and take the
// process down with it.
func (r *Runner) runOne(ctx context.Context, job Job) (didWork bool) {
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Errorw("Job tick panicked",
				zap.String("job", job.Name()),
				zap.Any("panic", rec),
			)
		}
	}()

	ok, err := job.Tick(ctx)
	if ok {
		didWork = true
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Warnw("Job tick failed",
			zap.String("job", job.Name()),
			zap.Error(err),
		)
	}

	return didWork
}
