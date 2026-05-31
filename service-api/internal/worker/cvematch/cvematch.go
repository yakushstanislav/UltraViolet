// Package cvematch is the periodic CVE matcher worker.
//
// Every CVE_MATCH_INTERVAL it scans services whose fingerprint changed since
// the last match pass and re-runs the matcher. It also re-evaluates every
// fingerprinted service after a catalog update so newly-published CVEs are
// surfaced without waiting for a fresh scan.
package cvematch

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	cvecatalog "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/catalog"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Matcher is the inline service used by the worker.
type Matcher interface {
	MatchService(ctx context.Context, serviceID uint64) (int, error)
}

// Config controls the worker cadence, batch size and parallelism.
type Config struct {
	Enabled     bool          `env:"CVE_MATCH_ENABLED"    env-default:"true"`
	Interval    time.Duration `env:"CVE_MATCH_INTERVAL"   env-default:"15m"`
	BatchSize   int           `env:"CVE_MATCH_BATCH"      env-default:"500"`
	Concurrency int           `env:"CVE_MATCH_CONCURRENCY" env-default:"8"`
}

// Job is the worker.Job implementation.
type Job struct {
	cfg              Config
	pool             *pgxpool.Pool
	catalog          cvecatalog.Repository
	matcher          Matcher
	logger           *zap.SugaredLogger
	lastRunAt        time.Time
	lastCatalogMTime sql.NullTime
}

// New builds a Job.
func New(
	cfg Config,
	pool *pgxpool.Pool,
	catalog cvecatalog.Repository,
	matcher Matcher,
	logger *zap.SugaredLogger,
) *Job {
	return &Job{
		cfg:     cfg,
		pool:    pool,
		catalog: catalog,
		matcher: matcher,
		logger:  logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "cve_match" }

// Tick implements worker.Job.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if !j.cfg.Enabled || j.matcher == nil {
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

	catalogMTime, err := j.catalog.MaxLastModifiedAt(ctx)
	if err != nil {
		return false, fmt.Errorf("can't read catalog mtime: %w", err)
	}

	catalogChanged := false

	if catalogMTime.Valid {
		if !j.lastCatalogMTime.Valid || catalogMTime.Time.After(j.lastCatalogMTime.Time) {
			catalogChanged = true
		}
	}

	serviceIDs, err := j.collectCandidates(ctx, catalogChanged)
	if err != nil {
		return false, err
	}

	if len(serviceIDs) == 0 {
		j.lastCatalogMTime = catalogMTime

		return false, nil
	}

	concurrency := j.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	if concurrency > len(serviceIDs) {
		concurrency = len(serviceIDs)
	}

	jobsCh := make(chan uint64)
	doneCh := make(chan struct{})

	for range concurrency {
		go func() {
			defer func() { doneCh <- struct{}{} }()

			for serviceID := range jobsCh {
				j.matchOne(ctx, serviceID)
			}
		}()
	}

dispatch:
	for _, serviceID := range serviceIDs {
		select {
		case <-ctx.Done():
			break dispatch
		case jobsCh <- serviceID:
		}
	}

	close(jobsCh)

	for range concurrency {
		<-doneCh
	}

	if ctx.Err() != nil {
		return true, ctx.Err()
	}

	j.lastCatalogMTime = catalogMTime
	j.logger.Infow("CVE match pass complete",
		zap.Int("services", len(serviceIDs)),
		zap.Int("concurrency", concurrency),
	)

	return true, nil
}

// matchOne wraps a single MatchService call with panic recovery so a single
// malformed fingerprint can't crash the worker pool and put the pod into
// CrashLoopBackoff. Returning quietly is the right behaviour: the row stays
// dirty and the next tick (or the next probe-driven enqueue) will retry it.
func (j *Job) matchOne(ctx context.Context, serviceID uint64) {
	defer func() {
		if r := recover(); r != nil {
			j.logger.Errorw("CVE match panicked",
				zap.Uint64("service_id", serviceID),
				zap.Any("panic", r),
			)
		}
	}()

	if _, err := j.matcher.MatchService(ctx, serviceID); err != nil {
		j.logger.Warnw("CVE match failed",
			zap.Uint64("service_id", serviceID),
			zap.Error(err),
		)
	}
}

func (j *Job) collectCandidates(ctx context.Context, catalogChanged bool) ([]uint64, error) {
	batch := j.cfg.BatchSize
	if batch <= 0 {
		batch = 500
	}

	// Distinct: since migration 16 one service can have several
	// uv_service_fingerprint rows (one per stack layer); we still want
	// each service_id only once per pass.
	builder := sq.Select("DISTINCT fp.service_id").
		From("uv_service_fingerprint fp").
		OrderBy("fp.service_id ASC").
		Limit(uint64(batch))

	if !catalogChanged {
		// Components written by a fresh probe carry per-component hashes
		// (FingerprintHash() over product/version/source), while completed
		// matches stamp every row of the service with the *set* hash
		// (SetHashOfComponents). Any divergence between fp.fingerprint_hash
		// and ms.fingerprint_hash means at least one component changed.
		builder = builder.
			LeftJoin("uv_service_match_state ms ON ms.service_id = fp.service_id").
			Where(squirrel.Or{
				squirrel.Eq{"ms.service_id": nil},
				squirrel.Expr("fp.fingerprint_hash IS DISTINCT FROM ms.fingerprint_hash"),
			})
	}
	// else: fall back to full rebuild – every fingerprinted service is a
	// candidate, bounded by LIMIT so we don't melt the pool when the catalog
	// churns.

	query, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build cve match candidates query: %w", err)
	}

	rows, err := j.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query cve match candidates: %w", err)
	}

	defer rows.Close()

	out := make([]uint64, 0, batch)

	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("can't scan candidate service id: %w", err)
		}

		out = append(out, id)
	}

	return out, rows.Err()
}
