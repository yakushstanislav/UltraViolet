// Package hostriskaggregate is the periodic host risk aggregation worker.
package hostriskaggregate

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/riskmetrics"
	hostrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	hostsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/host"
)

// Config controls the worker cadence and batch size.
type Config struct {
	Enabled   bool          `env:"HOST_RISK_ENABLED"  env-default:"true"`
	Interval  time.Duration `env:"HOST_RISK_INTERVAL" env-default:"15m"`
	Batch     int           `env:"HOST_RISK_BATCH"    env-default:"500"`
	Threshold int32         `env:"HOST_RISK_THRESHOLD" env-default:"65"`
}

// Aggregator recomputes persisted host risk scores.
type Aggregator interface {
	AggregateForHost(ctx context.Context, hostID uint64) error
}

// Job is the worker.Job implementation.
type Job struct {
	cfg            Config
	hostRepository hostrepository.Repository
	aggregator     Aggregator
	logger         *zap.SugaredLogger
	lastRunAt      time.Time
}

// New builds a Job.
func New(
	cfg Config,
	hostRepository hostrepository.Repository,
	aggregator Aggregator,
	logger *zap.SugaredLogger,
) *Job {
	return &Job{
		cfg:            cfg,
		hostRepository: hostRepository,
		aggregator:     aggregator,
		logger:         logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "host_risk_aggregate" }

// Tick implements worker.Job.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if !j.cfg.Enabled || j.aggregator == nil {
		return false, nil
	}

	interval := j.cfg.Interval
	if interval <= 0 {
		interval = 15 * time.Minute
	}

	now := time.Now().UTC()

	if !j.lastRunAt.IsZero() && now.Sub(j.lastRunAt) < interval {
		return false, nil
	}

	j.lastRunAt = now

	hostIDs, err := j.hostRepository.ListHostsNeedingRiskUpdate(ctx, j.cfg.Batch)
	if err != nil {
		return false, fmt.Errorf("can't list hosts needing risk update: %w", err)
	}

	if len(hostIDs) == 0 {
		return false, nil
	}

	for _, hostID := range hostIDs {
		if err := j.aggregator.AggregateForHost(hostsvc.WithTrigger(ctx, riskmetrics.TriggerPeriodic), hostID); err != nil {
			j.logger.Warnw("Host risk aggregate failed",
				zap.Uint64("host_id", hostID),
				zap.Error(err),
			)
		}
	}

	j.logger.Infow("Host risk aggregate pass complete", zap.Int("hosts", len(hostIDs)))

	return true, nil
}

// Ensure RiskService satisfies Aggregator at compile time.
var _ Aggregator = (*hostsvc.RiskService)(nil)
