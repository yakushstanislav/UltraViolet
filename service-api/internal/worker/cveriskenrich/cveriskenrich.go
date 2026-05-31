// Package cveriskenrich periodically syncs CISA KEV and FIRST EPSS into
// uv_cve. The job is independent from cvesync: it never adds new CVE rows,
// only annotates ones already present (so a stale catalog won't grow risk
// metadata for vulnerabilities the matcher can't surface).
package cveriskenrich

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cverisk"
	cvecatalog "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/catalog"
)

// Config controls the cadence. Both feeds are tiny (~MB), so the default
// daily interval is conservative enough to stay polite while still catching
// new KEV adds within hours.
type Config struct {
	Enabled  bool          `env:"CVE_RISK_ENABLED"  env-default:"true"`
	Interval time.Duration `env:"CVE_RISK_INTERVAL" env-default:"24h"`
}

// Job is the worker.Job implementation.
type Job struct {
	cfg       Config
	client    *cverisk.Client
	catalog   cvecatalog.Repository
	logger    *zap.SugaredLogger
	lastRunAt time.Time
}

// New builds a Job.
func New(
	cfg Config,
	client *cverisk.Client,
	catalog cvecatalog.Repository,
	logger *zap.SugaredLogger,
) *Job {
	return &Job{cfg: cfg, client: client, catalog: catalog, logger: logger}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "cve_risk_enrich" }

// Tick implements worker.Job.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if !j.cfg.Enabled || j.client == nil {
		return false, nil
	}

	interval := j.cfg.Interval
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	now := time.Now().UTC()

	if !j.lastRunAt.IsZero() && now.Sub(j.lastRunAt) < interval {
		return false, nil
	}

	j.lastRunAt = now

	if err := j.refreshKEV(ctx, now); err != nil {
		j.logger.Warnw("KEV refresh failed", zap.Error(err))
	}

	if err := j.refreshEPSS(ctx, now); err != nil {
		j.logger.Warnw("EPSS refresh failed", zap.Error(err))
	}

	return true, nil
}

func (j *Job) refreshKEV(ctx context.Context, now time.Time) error {
	entries, err := j.client.FetchKEV(ctx)
	if err != nil {
		return fmt.Errorf("fetch KEV: %w", err)
	}

	rows := make([]cvecatalog.KEVRow, 0, len(entries))

	for _, entry := range entries {
		rows = append(rows, cvecatalog.KEVRow{
			CVEID:           entry.CVEID,
			AddedAt:         nullTimeOrZero(entry.AddedAt),
			DueDate:         nullTimeOrZero(entry.DueDate),
			KnownRansomware: sql.NullBool{Bool: entry.KnownRansomware, Valid: true},
		})
	}

	updated, err := j.catalog.ApplyKEV(ctx, rows)
	if err != nil {
		return fmt.Errorf("apply KEV: %w", err)
	}

	j.logger.Infow("KEV refreshed",
		zap.Int("entries", len(rows)),
		zap.Int("updated", updated),
		zap.Time("at", now),
	)

	return nil
}

func (j *Job) refreshEPSS(ctx context.Context, now time.Time) error {
	entries, err := j.client.FetchEPSS(ctx)
	if err != nil {
		return fmt.Errorf("fetch EPSS: %w", err)
	}

	rows := make([]cvecatalog.EPSSRow, 0, len(entries))

	for _, entry := range entries {
		rows = append(rows, cvecatalog.EPSSRow{
			CVEID:      entry.CVEID,
			Score:      entry.Score,
			Percentile: entry.Percentile,
			ScoredAt:   now,
		})
	}

	updated, err := j.catalog.ApplyEPSS(ctx, rows)
	if err != nil {
		return fmt.Errorf("apply EPSS: %w", err)
	}

	j.logger.Infow("EPSS refreshed",
		zap.Int("entries", len(rows)),
		zap.Int("updated", updated),
		zap.Time("at", now),
	)

	return nil
}

func nullTimeOrZero(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}

	return sql.NullTime{Time: t, Valid: true}
}
