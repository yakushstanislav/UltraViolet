// Package retention periodically prunes large rows from history tables.
package retention

import (
	"context"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Config controls retention windows. Zero disables the corresponding pruner.
type Config struct {
	SnapshotKeep       time.Duration `env:"RETENTION_SNAPSHOTS"        env-default:"720h"`
	AlertEventsKeep    time.Duration `env:"RETENTION_ALERT_EVENTS"     env-default:"720h"`
	ChangeEventsKeep   time.Duration `env:"RETENTION_CHANGE_EVENTS"    env-default:"2160h"`
	HTTPBodyKeep       time.Duration `env:"RETENTION_HTTP_BODY"        env-default:"720h"`
	HTTPScreenshotKeep time.Duration `env:"RETENTION_HTTP_SCREENSHOTS" env-default:"720h"`
	TickEvery          time.Duration `env:"RETENTION_TICK_EVERY"       env-default:"6h"`
}

// Job runs DELETE/UPDATE statements according to the configured windows.
type Job struct {
	pool      *pgxpool.Pool
	cfg       Config
	logger    *zap.SugaredLogger
	lastRunAt time.Time
}

// New builds a Job.
func New(pool *pgxpool.Pool, cfg Config, logger *zap.SugaredLogger) *Job {
	return &Job{pool: pool, cfg: cfg, logger: logger}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "retention" }

// Tick implements worker.Job. The job throttles itself to TickEvery so the
// runner can call it on every poll without doing real work each time.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if j.cfg.TickEvery <= 0 {
		j.cfg.TickEvery = 6 * time.Hour
	}

	now := time.Now().UTC()

	if !j.lastRunAt.IsZero() && now.Sub(j.lastRunAt) < j.cfg.TickEvery {
		return false, nil
	}

	j.lastRunAt = now

	j.prune(ctx, now, "uv_service_snapshot", "created_at", j.cfg.SnapshotKeep,
		func(cutoff time.Time) squirrel.Sqlizer {
			return sq.Delete("uv_service_snapshot").Where(squirrel.Lt{"created_at": cutoff})
		})

	j.prune(ctx, now, "uv_alert_event", "created_at", j.cfg.AlertEventsKeep,
		func(cutoff time.Time) squirrel.Sqlizer {
			return sq.Delete("uv_alert_event").Where(squirrel.Lt{"created_at": cutoff})
		})

	j.prune(ctx, now, "uv_service_change_event", "created_at", j.cfg.ChangeEventsKeep,
		func(cutoff time.Time) squirrel.Sqlizer {
			return sq.Delete("uv_service_change_event").Where(squirrel.Lt{"created_at": cutoff})
		})

	j.prune(ctx, now, "uv_http_response.body", "captured_at", j.cfg.HTTPBodyKeep,
		func(cutoff time.Time) squirrel.Sqlizer {
			return sq.Update("uv_http_response").
				Set("body", nil).
				Where(squirrel.NotEq{"body": nil}).
				Where(squirrel.Lt{"captured_at": cutoff})
		})

	j.prune(ctx, now, "uv_http_screenshot", "captured_at", j.cfg.HTTPScreenshotKeep,
		func(cutoff time.Time) squirrel.Sqlizer {
			return sq.Delete("uv_http_screenshot").Where(squirrel.Lt{"captured_at": cutoff})
		})

	return true, nil
}

// prune runs one retention sweep with full audit logging. Negative or zero
// keep durations skip the sweep. A cutoff that would land in the future
// (mis-configured RETENTION_*) is rejected before any DELETE/UPDATE so a
// duration sign-flip can't accidentally wipe every row.
func (j *Job) prune(
	ctx context.Context,
	now time.Time,
	target string,
	column string,
	keep time.Duration,
	build func(cutoff time.Time) squirrel.Sqlizer,
) {
	if keep <= 0 {
		return
	}

	cutoff := now.Add(-keep)
	if !cutoff.Before(now) {
		j.logger.Warnw("Retention cutoff is not in the past, skipping",
			zap.String("target", target),
			zap.String("column", column),
			zap.Duration("keep", keep),
			zap.Time("cutoff", cutoff),
		)

		return
	}

	n, err := j.exec(ctx, build(cutoff))
	if err != nil {
		j.logger.Warnw("Retention prune failed",
			zap.String("target", target),
			zap.String("column", column),
			zap.Time("cutoff", cutoff),
			zap.Error(err),
		)

		return
	}

	j.logger.Infow("Retention prune",
		zap.String("target", target),
		zap.String("column", column),
		zap.Time("cutoff", cutoff),
		zap.Int64("rows", n),
	)
}

func (j *Job) exec(ctx context.Context, builder squirrel.Sqlizer) (int64, error) {
	query, args, err := builder.ToSql()
	if err != nil {
		return 0, fmt.Errorf("retention build query: %w", err)
	}

	tag, err := j.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("retention query failed: %w", err)
	}

	return tag.RowsAffected(), nil
}
