// Package risksnapshot is the retention worker for uv_host_risk_snapshot and
// uv_service_risk_snapshot. Snapshot appends happen inline in services/host on
// every host recompute (with min-delta / max-idle dedup); this worker only
// prunes rows past the configured retention window.
package risksnapshot

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/riskmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/remediation"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/risksnapshot"
)

// Config controls the worker cadence and pruning policy.
type Config struct {
	Enabled       bool          `env:"RISK_SNAPSHOT_ENABLED"  env-default:"true"`
	Interval      time.Duration `env:"RISK_SNAPSHOT_INTERVAL" env-default:"1h"`
	MinDelta      int32         `env:"RISK_SNAPSHOT_MIN_DELTA" env-default:"2"`
	RetentionDays int           `env:"RISK_EVENT_RETENTION_DAYS" env-default:"180"`
}

// Job is the worker.Job implementation.
type Job struct {
	cfg                   Config
	snapshotRepository    risksnapshot.Repository
	remediationRepository remediation.Repository
	logger                *zap.SugaredLogger
	lastRunAt             time.Time
}

// New builds a Job.
func New(
	cfg Config,
	snapshotRepository risksnapshot.Repository,
	remediationRepository remediation.Repository,
	logger *zap.SugaredLogger,
) *Job {
	return &Job{
		cfg:                   cfg,
		snapshotRepository:    snapshotRepository,
		remediationRepository: remediationRepository,
		logger:                logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "risk_snapshot_retention" }

// Tick implements worker.Job. Prunes uv_host_risk_snapshot and
// uv_service_risk_snapshot rows older than the configured retention window.
// Snapshot appends are driven inline by the host risk service on every
// recompute.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if !j.cfg.Enabled {
		return false, nil
	}

	interval := j.cfg.Interval
	if interval <= 0 {
		interval = time.Hour
	}

	now := time.Now().UTC()

	if !j.lastRunAt.IsZero() && now.Sub(j.lastRunAt) < interval {
		return false, nil
	}

	j.lastRunAt = now

	if j.cfg.RetentionDays <= 0 {
		return false, nil
	}

	cutoff := now.Add(-time.Duration(j.cfg.RetentionDays) * 24 * time.Hour)

	snapshotPruned, err := j.snapshotRepository.PruneOlderThan(ctx, cutoff)
	if err != nil {
		j.logger.Warnw("Risk snapshot prune failed", zap.Error(err))

		snapshotPruned = 0
	}

	if snapshotPruned > 0 {
		j.logger.Infow("Risk retention sweep complete",
			zap.Int64("snapshot_rows", snapshotPruned),
			zap.Time("cutoff", cutoff),
		)
	}

	if openCount, err := j.remediationRepository.CountOpen(ctx); err == nil {
		riskmetrics.RemediationRecommendationsOpen.Set(float64(openCount))
	} else {
		j.logger.Warnw("Can't sample open remediations gauge", zap.Error(err))
	}

	return snapshotPruned > 0, nil
}
