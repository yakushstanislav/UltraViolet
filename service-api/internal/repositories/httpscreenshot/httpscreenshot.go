// Package httpscreenshot stores headless-Chromium rendered thumbnails for HTTP
// services and exposes the small job queue consumed by the screenshot worker.
package httpscreenshot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

const (
	// JobStatusPending marks a job that is waiting to be claimed by a worker.
	JobStatusPending = "pending"
	// JobStatusRunning marks a job that has been claimed and is currently
	// being processed.
	JobStatusRunning = "running"
	// JobStatusFailed marks a job that exceeded its attempt budget.
	JobStatusFailed = "failed"
)

// Screenshot is the persisted thumbnail for one HTTP service.
type Screenshot struct {
	ServiceID       uint64
	BodySHA256      sql.NullString
	Thumbnail       []byte
	ThumbnailWidth  int
	ThumbnailHeight int
	RenderMS        int
	CapturedAt      time.Time
}

// Job is a queued render task for one HTTP service.
type Job struct {
	ServiceID  uint64
	Status     string
	Attempts   int
	LastError  sql.NullString
	EnqueuedAt time.Time
	UpdatedAt  time.Time
}

// Repository is the storage contract for HTTP screenshots and their job queue.
type Repository interface {
	Upsert(ctx context.Context, screenshot *Screenshot) error
	Get(ctx context.Context, serviceID uint64) (*Screenshot, error)
	GetByHostIPAndServiceID(ctx context.Context, ip netip.Addr, serviceID uint64) (*Screenshot, error)
	HasScreenshotByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]bool, error)
	EnqueueIfStale(ctx context.Context, serviceID uint64, bodySHA256 sql.NullString) error
	ClaimPending(ctx context.Context, limit int) ([]Job, error)
	MarkFailed(ctx context.Context, serviceID uint64, message string, terminal bool) error
	DeleteJob(ctx context.Context, serviceID uint64) error
	PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	QueueDepth(ctx context.Context) (map[string]int64, error)
	WithTx(tx pgx.Tx) Repository
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	db pgkit.Querier
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{db: pool}
}

// WithTx returns a Repository that routes every query through tx.
func (p *PostgreSQL) WithTx(tx pgx.Tx) Repository {
	return &PostgreSQL{db: tx}
}

// Upsert stores or refreshes the thumbnail for the given service.
func (p *PostgreSQL) Upsert(ctx context.Context, screenshot *Screenshot) error {
	if screenshot == nil {
		return errors.New("screenshot is nil")
	}

	capturedAt := screenshot.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}

	query, args, err := sq.Insert("uv_http_screenshot").
		Columns(
			"service_id", "body_sha256", "thumbnail",
			"thumbnail_width", "thumbnail_height",
			"render_ms", "captured_at",
		).
		Values(
			screenshot.ServiceID,
			screenshot.BodySHA256,
			screenshot.Thumbnail,
			screenshot.ThumbnailWidth,
			screenshot.ThumbnailHeight,
			screenshot.RenderMS,
			capturedAt,
		).
		Suffix(`ON CONFLICT (service_id) DO UPDATE SET
    body_sha256      = EXCLUDED.body_sha256,
    thumbnail        = EXCLUDED.thumbnail,
    thumbnail_width  = EXCLUDED.thumbnail_width,
    thumbnail_height = EXCLUDED.thumbnail_height,
    render_ms        = EXCLUDED.render_ms,
    captured_at      = EXCLUDED.captured_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert HTTP screenshot query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert HTTP screenshot: %w", pgkit.Handle(err))
	}

	return nil
}

// Get returns the persisted thumbnail for one service, or pgkit.ErrNoRows.
func (p *PostgreSQL) Get(ctx context.Context, serviceID uint64) (*Screenshot, error) {
	query, args, err := sq.Select(
		"service_id", "body_sha256", "thumbnail",
		"thumbnail_width", "thumbnail_height",
		"render_ms", "captured_at",
	).
		From("uv_http_screenshot").
		Where(squirrel.Eq{"service_id": serviceID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get HTTP screenshot query: %w", err)
	}

	var screenshot Screenshot

	err = p.db.QueryRow(ctx, query, args...).Scan(
		&screenshot.ServiceID,
		&screenshot.BodySHA256,
		&screenshot.Thumbnail,
		&screenshot.ThumbnailWidth,
		&screenshot.ThumbnailHeight,
		&screenshot.RenderMS,
		&screenshot.CapturedAt,
	)
	if err != nil {
		return nil, pgkit.Handle(err)
	}

	return &screenshot, nil
}

// GetByHostIPAndServiceID returns the persisted thumbnail when the given
// service id belongs to a host with the given IP. This ownership check keeps
// callers from leaking screenshots across hosts via a path-only join.
func (p *PostgreSQL) GetByHostIPAndServiceID(ctx context.Context, ip netip.Addr, serviceID uint64) (*Screenshot, error) {
	query, args, err := sq.Select(
		"scrn.service_id",
		"scrn.body_sha256",
		"scrn.thumbnail",
		"scrn.thumbnail_width",
		"scrn.thumbnail_height",
		"scrn.render_ms",
		"scrn.captured_at",
	).
		From("uv_http_screenshot AS scrn").
		Join("uv_service AS svc ON svc.id = scrn.service_id").
		Join("uv_host AS h ON h.id = svc.host_id").
		Where(squirrel.Eq{"scrn.service_id": serviceID}).
		Where("h.ip = ?::inet", ip.String()).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build host-scoped get HTTP screenshot query: %w", err)
	}

	var screenshot Screenshot

	if err := p.db.QueryRow(ctx, query, args...).Scan(
		&screenshot.ServiceID,
		&screenshot.BodySHA256,
		&screenshot.Thumbnail,
		&screenshot.ThumbnailWidth,
		&screenshot.ThumbnailHeight,
		&screenshot.RenderMS,
		&screenshot.CapturedAt,
	); err != nil {
		return nil, pgkit.Handle(err)
	}

	return &screenshot, nil
}

// HasScreenshotByServiceIDs returns the subset of service ids that already
// have a rendered thumbnail. Ids not present in the map should be treated as
// not having a screenshot yet.
func (p *PostgreSQL) HasScreenshotByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]bool, error) {
	out := make(map[uint64]bool, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select("service_id").
		From("uv_http_screenshot").
		Where("service_id = ANY(?)", serviceIDs).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build has-screenshot query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query has-screenshot: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("can't scan has-screenshot row: %w", pgkit.Handle(err))
		}

		out[id] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate has-screenshot rows: %w", err)
	}

	return out, nil
}

// EnqueueIfStale inserts a pending job for the service unless an up-to-date
// screenshot already exists for the same body hash. Re-enqueues a finished
// job (resets attempts) so transient failures get retried after the next
// probe pass.
func (p *PostgreSQL) EnqueueIfStale(ctx context.Context, serviceID uint64, bodySHA256 sql.NullString) error {
	now := time.Now().UTC()

	// Postgres allows a CTE to short-circuit if a fresh screenshot exists.
	const stmt = `
WITH fresh AS (
    SELECT 1 FROM uv_http_screenshot
    WHERE service_id = $1
      AND $2::text IS NOT NULL
      AND body_sha256 IS NOT NULL
      AND body_sha256 = $2::text
)
INSERT INTO uv_http_screenshot_job (service_id, status, attempts, last_error, enqueued_at, updated_at)
SELECT $1, 'pending', 0, NULL, $3, $3
WHERE NOT EXISTS (SELECT 1 FROM fresh)
ON CONFLICT (service_id) DO UPDATE SET
    status      = 'pending',
    attempts    = 0,
    last_error  = NULL,
    enqueued_at = EXCLUDED.enqueued_at,
    updated_at  = EXCLUDED.updated_at
WHERE uv_http_screenshot_job.status <> 'running'`

	if _, err := p.db.Exec(ctx, stmt, serviceID, bodySHA256, now); err != nil {
		return fmt.Errorf("can't enqueue HTTP screenshot job: %w", pgkit.Handle(err))
	}

	return nil
}

// ClaimPending atomically transitions up to limit pending jobs into running
// state and returns the claimed rows. Uses FOR UPDATE SKIP LOCKED so multiple
// workers can claim disjoint batches concurrently.
func (p *PostgreSQL) ClaimPending(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 {
		return nil, nil
	}

	const stmt = `
WITH claimed AS (
    SELECT service_id
    FROM uv_http_screenshot_job
    WHERE status = 'pending'
    ORDER BY enqueued_at
    FOR UPDATE SKIP LOCKED
    LIMIT $1
)
UPDATE uv_http_screenshot_job AS j
SET status = 'running',
    attempts = j.attempts + 1,
    updated_at = $2
FROM claimed
WHERE j.service_id = claimed.service_id
RETURNING j.service_id, j.status, j.attempts, j.last_error, j.enqueued_at, j.updated_at`

	rows, err := p.db.Query(ctx, stmt, limit, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("can't claim HTTP screenshot jobs: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var jobs []Job

	for rows.Next() {
		var job Job

		if err := rows.Scan(
			&job.ServiceID,
			&job.Status,
			&job.Attempts,
			&job.LastError,
			&job.EnqueuedAt,
			&job.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("can't scan claimed job: %w", pgkit.Handle(err))
		}

		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate claimed jobs: %w", err)
	}

	return jobs, nil
}

// MarkFailed records a render error for the job. When terminal=true the job
// transitions to 'failed' so it won't be claimed again; otherwise it's reset
// to 'pending' for another attempt on the next tick. Returns pgkit.ErrNoRows
// when the job row no longer exists so the worker can tell "already gone"
// (e.g. pruned by retention) from a real DB error.
func (p *PostgreSQL) MarkFailed(ctx context.Context, serviceID uint64, message string, terminal bool) error {
	status := JobStatusPending
	if terminal {
		status = JobStatusFailed
	}

	query, args, err := sq.Update("uv_http_screenshot_job").
		Set("status", status).
		Set("last_error", message).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"service_id": serviceID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build mark-failed query: %w", err)
	}

	tag, err := p.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't mark HTTP screenshot job failed: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return pgkit.ErrNoRows
	}

	return nil
}

// DeleteJob removes the job row once the screenshot has been stored.
func (p *PostgreSQL) DeleteJob(ctx context.Context, serviceID uint64) error {
	query, args, err := sq.Delete("uv_http_screenshot_job").
		Where(squirrel.Eq{"service_id": serviceID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build delete-job query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't delete HTTP screenshot job: %w", pgkit.Handle(err))
	}

	return nil
}

// PruneOlderThan deletes screenshots captured before cutoff and returns the
// number of removed rows.
func (p *PostgreSQL) PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	query, args, err := sq.Delete("uv_http_screenshot").
		Where(squirrel.Lt{"captured_at": cutoff}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build prune query: %w", err)
	}

	tag, err := p.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("can't prune HTTP screenshots: %w", pgkit.Handle(err))
	}

	return tag.RowsAffected(), nil
}

// QueueDepth returns a status → count map for observability.
func (p *PostgreSQL) QueueDepth(ctx context.Context) (map[string]int64, error) {
	query, args, err := sq.Select("status", "count(*)").
		From("uv_http_screenshot_job").
		GroupBy("status").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build queue-depth query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query queue depth: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make(map[string]int64, 3)

	for rows.Next() {
		var (
			status string
			count  int64
		)

		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("can't scan queue depth row: %w", pgkit.Handle(err))
		}

		out[status] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate queue depth rows: %w", err)
	}

	return out, nil
}
