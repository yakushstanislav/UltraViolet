// Package delta tracks per-scan change events between consecutive scan runs.
package delta

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/timeseries"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// ChangeKind names a row in uv_service_change_event.change_type. The empty
// value means "any kind" (used by callers that aggregate across all kinds).
type ChangeKind string

const (
	// ChangeKindAny matches every kind — used as a sentinel by callers that
	// want a total, not a per-kind count.
	ChangeKindAny ChangeKind = ""
	// ChangeKindNew flags services that appeared in this scan.
	ChangeKindNew ChangeKind = "new"
	// ChangeKindDisappeared flags services that vanished since the previous scan.
	ChangeKindDisappeared ChangeKind = "disappeared"
	// ChangeKindChanged flags services whose banner/title/status/TLS shifted.
	ChangeKindChanged ChangeKind = "changed"
)

// Summary holds aggregated new/disappeared/changed counts for one scan pair.
type Summary struct {
	ScanID              uint64
	PreviousScanID      sql.NullInt64
	NewServices         int32
	DisappearedServices int32
	ChangedServices     int32
	CreatedAt           time.Time
}

// ChangeEvent is one row from uv_service_change_event.
type ChangeEvent struct {
	ID             uint64
	ScanID         uint64
	HostID         uint64
	ServiceID      sql.NullInt64
	PreviousScanID sql.NullInt64
	ChangeType     ChangeKind
	Details        map[string]any
	CreatedAt      time.Time
}

// Repository is the storage contract for scan delta data.
type Repository interface {
	BuildAndStore(ctx context.Context, scanID uint64) error
	GetSummary(ctx context.Context, scanID uint64) (*Summary, error)
	GetHostTimeline(ctx context.Context, ip netip.Addr, limit, offset uint64) ([]*ChangeEvent, uint64, error)
	GetScanEvents(ctx context.Context, scanID, limit, offset uint64) ([]*ChangeEvent, uint64, error)
	CountChangesSince(ctx context.Context, since time.Time, kind ChangeKind) (uint64, error)
	CountChangesByKindSince(ctx context.Context, since time.Time) (ChangeKindCounts, error)
	BucketedChangesSince(ctx context.Context, since time.Time, bucket string, kind ChangeKind) (map[time.Time]uint64, error)
	StreamChangeEvents(ctx context.Context, scanID uint64, fn func(*ChangeEvent) error) error
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

// BuildAndStore computes and persists the delta between the previous and current scan.
func (p *PostgreSQL) BuildAndStore(ctx context.Context, scanID uint64) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can't begin delta tx: %w", pgkit.Handle(err))
	}

	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
INSERT INTO uv_service_snapshot(scan_id, host_id, service_id, ip, port, transport, protocol, banner_hash, title, status_code, tls_fp, created_at)
SELECT $1, h.id, svc.id, h.ip, svc.port, svc.transport, svc.protocol, svc.banner_hash, hr.title, hr.status_code, cert.fingerprint_sha256, $2
FROM uv_service svc
JOIN uv_host h ON h.id = svc.host_id
LEFT JOIN uv_http_response hr ON hr.service_id = svc.id
LEFT JOIN uv_tls_certificate cert ON cert.service_id = svc.id
WHERE svc.last_seen >= (SELECT started_at FROM uv_scan WHERE id = $1)
ON CONFLICT DO NOTHING
`, scanID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("can't store snapshot: %w", pgkit.Handle(err))
	}

	now := time.Now().UTC()

	prevScanQuery, prevScanArgs, err := sq.Select("id").
		From("uv_scan").
		Where(squirrel.Lt{"id": scanID}).
		Where(squirrel.Eq{"status": "DONE"}).
		OrderBy("id DESC").
		Limit(1).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build previous scan id query: %w", err)
	}

	var prevScanID sql.NullInt64

	err = tx.QueryRow(ctx, prevScanQuery, prevScanArgs...).Scan(&prevScanID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("can't read previous scan id: %w", pgkit.Handle(err))
	}

	if prevScanID.Valid {
		_, err = tx.Exec(ctx, `
INSERT INTO uv_service_change_event(scan_id, host_id, service_id, previous_scan_id, change_type, details, created_at)
SELECT $1, c.host_id, c.service_id, $2, 'new',
       jsonb_build_object(
         'ip', host(c.ip),
         'port', c.port,
         'transport', c.transport::text,
         'protocol', c.protocol,
         'banner_hash', c.banner_hash,
         'title', c.title,
         'status_code', c.status_code,
         'tls_fp', c.tls_fp
       ),
       $3
FROM uv_service_snapshot c
LEFT JOIN uv_service_snapshot p ON p.scan_id = $2 AND p.service_id = c.service_id
WHERE c.scan_id = $1 AND p.service_id IS NULL
`, scanID, prevScanID.Int64, now)
		if err != nil {
			return fmt.Errorf("can't store new change events: %w", pgkit.Handle(err))
		}

		_, err = tx.Exec(ctx, `
INSERT INTO uv_service_change_event(scan_id, host_id, service_id, previous_scan_id, change_type, details, created_at)
SELECT $1, p.host_id, p.service_id, $2, 'disappeared',
       jsonb_build_object(
         'ip', host(p.ip),
         'port', p.port,
         'transport', p.transport::text,
         'protocol', p.protocol,
         'banner_hash', p.banner_hash,
         'title', p.title,
         'status_code', p.status_code,
         'tls_fp', p.tls_fp
       ),
       $3
FROM uv_service_snapshot p
LEFT JOIN uv_service_snapshot c ON c.scan_id = $1 AND c.service_id = p.service_id
WHERE p.scan_id = $2 AND c.service_id IS NULL
`, scanID, prevScanID.Int64, now)
		if err != nil {
			return fmt.Errorf("can't store disappeared change events: %w", pgkit.Handle(err))
		}

		_, err = tx.Exec(ctx, `
INSERT INTO uv_service_change_event(scan_id, host_id, service_id, previous_scan_id, change_type, details, created_at)
SELECT $1, c.host_id, c.service_id, $2, 'changed',
       jsonb_build_object(
         'ip', host(c.ip),
         'port', c.port,
         'transport', c.transport::text,
         'protocol', c.protocol,
         'before', jsonb_build_object(
            'banner_hash', p.banner_hash,
            'title', p.title,
            'status_code', p.status_code,
            'tls_fp', p.tls_fp
         ),
         'after', jsonb_build_object(
            'banner_hash', c.banner_hash,
            'title', c.title,
            'status_code', c.status_code,
            'tls_fp', c.tls_fp
         )
       ),
       $3
FROM uv_service_snapshot c
JOIN uv_service_snapshot p ON p.scan_id = $2 AND p.service_id = c.service_id
WHERE c.scan_id = $1
  AND (
    c.banner_hash IS DISTINCT FROM p.banner_hash
    OR c.title IS DISTINCT FROM p.title
    OR c.status_code IS DISTINCT FROM p.status_code
    OR c.tls_fp IS DISTINCT FROM p.tls_fp
  )
`, scanID, prevScanID.Int64, now)
		if err != nil {
			return fmt.Errorf("can't store changed change events: %w", pgkit.Handle(err))
		}
	}

	_, err = tx.Exec(ctx, `
INSERT INTO uv_scan_delta_summary(scan_id, previous_scan_id, new_services, disappeared_services, changed_services, created_at)
SELECT $1,
       $2,
       COALESCE(SUM(CASE WHEN change_type = 'new' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN change_type = 'disappeared' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN change_type = 'changed' THEN 1 ELSE 0 END), 0),
       $3
FROM uv_service_change_event WHERE scan_id = $1
ON CONFLICT (scan_id) DO UPDATE SET
  previous_scan_id = EXCLUDED.previous_scan_id,
  new_services = EXCLUDED.new_services,
  disappeared_services = EXCLUDED.disappeared_services,
  changed_services = EXCLUDED.changed_services
`, scanID, prevScanID, now)
	if err != nil {
		return fmt.Errorf("can't store delta summary: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("can't commit delta tx: %w", pgkit.Handle(err))
	}

	return nil
}

// GetSummary returns the delta summary row for scanID.
func (p *PostgreSQL) GetSummary(ctx context.Context, scanID uint64) (*Summary, error) {
	query, args, err := sq.Select(
		"scan_id", "previous_scan_id", "new_services", "disappeared_services", "changed_services", "created_at",
	).
		From("uv_scan_delta_summary").
		Where(squirrel.Eq{"scan_id": scanID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get delta summary query: %w", err)
	}

	out := &Summary{}

	if err := p.pool.QueryRow(ctx, query, args...).Scan(
		&out.ScanID, &out.PreviousScanID, &out.NewServices, &out.DisappearedServices, &out.ChangedServices, &out.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("can't get delta summary: %w", pgkit.Handle(err))
	}

	return out, nil
}

// GetHostTimeline returns paginated change events for a host IP ordered newest-first.
func (p *PostgreSQL) GetHostTimeline(ctx context.Context, ip netip.Addr, limit, offset uint64) ([]*ChangeEvent, uint64, error) {
	if limit == 0 {
		limit = 100
	}

	countSQL, countArgs, err := sq.Select("COUNT(*)").
		From("uv_service_change_event e").
		Join("uv_host h ON h.id = e.host_id").
		Where(squirrel.Eq{"h.ip": ip.String()}).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count host timeline query: %w", err)
	}

	var total uint64

	err = p.pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("can't count host timeline: %w", pgkit.Handle(err))
	}

	query, args, err := sq.Select(
		"e.id", "e.scan_id", "e.host_id", "e.service_id", "e.previous_scan_id", "e.change_type", "e.details", "e.created_at",
	).
		From("uv_service_change_event e").
		Join("uv_host h ON h.id = e.host_id").
		Where(squirrel.Eq{"h.ip": ip.String()}).
		OrderBy("e.id DESC").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list host timeline query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list host timeline: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*ChangeEvent

	for rows.Next() {
		item := &ChangeEvent{}

		var raw []byte

		if err := rows.Scan(
			&item.ID, &item.ScanID, &item.HostID, &item.ServiceID, &item.PreviousScanID, &item.ChangeType, &raw, &item.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("can't scan change event: %w", pgkit.Handle(err))
		}

		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &item.Details); err != nil {
				return nil, 0, fmt.Errorf("can't unmarshal change event details: %w", err)
			}
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate host timeline: %w", err)
	}

	return out, total, nil
}

// GetScanEvents returns paginated per-service change events for the given scan.
func (p *PostgreSQL) GetScanEvents(ctx context.Context, scanID, limit, offset uint64) ([]*ChangeEvent, uint64, error) {
	if limit == 0 {
		limit = 100
	}

	countQuery, countArgs, err := sq.Select("COUNT(*)").
		From("uv_service_change_event").
		Where(squirrel.Eq{"scan_id": scanID}).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count scan events query: %w", err)
	}

	var total uint64

	if err = p.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("can't count scan events: %w", pgkit.Handle(err))
	}

	query, args, err := sq.Select(
		"id", "scan_id", "host_id", "service_id", "previous_scan_id",
		"change_type", "details", "created_at",
	).
		From("uv_service_change_event").
		Where(squirrel.Eq{"scan_id": scanID}).
		OrderBy("id ASC").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list scan events query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list scan events: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*ChangeEvent

	for rows.Next() {
		item := &ChangeEvent{}

		var raw []byte

		if err := rows.Scan(
			&item.ID, &item.ScanID, &item.HostID, &item.ServiceID,
			&item.PreviousScanID, &item.ChangeType, &raw, &item.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("can't scan scan event: %w", pgkit.Handle(err))
		}

		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &item.Details); err != nil {
				return nil, 0, fmt.Errorf("can't unmarshal scan event details: %w", err)
			}
		}

		out = append(out, item)
	}

	return out, total, rows.Err()
}

// ChangeKindCounts holds delta event totals grouped by change_type for a time window.
type ChangeKindCounts struct {
	New         uint64
	Disappeared uint64
	Changed     uint64
}

// CountChangesByKindSince returns new/disappeared/changed counts since the given time in one query.
func (p *PostgreSQL) CountChangesByKindSince(ctx context.Context, since time.Time) (ChangeKindCounts, error) {
	query, args, err := sq.Select().
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE change_type = ?)", ChangeKindNew)).
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE change_type = ?)", ChangeKindDisappeared)).
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE change_type = ?)", ChangeKindChanged)).
		From("uv_service_change_event").
		Where("created_at >= ?", since).
		ToSql()
	if err != nil {
		return ChangeKindCounts{}, fmt.Errorf("can't build count changes by kind query: %w", err)
	}

	var out ChangeKindCounts

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&out.New, &out.Disappeared, &out.Changed); err != nil {
		return ChangeKindCounts{}, fmt.Errorf("can't count changes by kind: %w", pgkit.Handle(err))
	}

	return out, nil
}

// CountChangesSince returns the count of change events since the given time, optionally filtered by kind.
func (p *PostgreSQL) CountChangesSince(ctx context.Context, since time.Time, kind ChangeKind) (uint64, error) {
	q := sq.Select("COUNT(*)").From("uv_service_change_event").Where("created_at >= ?", since)

	if kind != ChangeKindAny {
		q = q.Where(squirrel.Eq{"change_type": string(kind)})
	}

	query, args, err := q.ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count changes since query: %w", err)
	}

	var n uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count change events since: %w", pgkit.Handle(err))
	}

	return n, nil
}

// BucketedChangesSince returns a time-bucketed histogram of change events since the given time.
func (p *PostgreSQL) BucketedChangesSince(ctx context.Context, since time.Time, bucket string, kind ChangeKind) (map[time.Time]uint64, error) {
	q := sq.Select().
		Column(squirrel.Expr("date_trunc(?, created_at) AS b", bucket)).
		Column("COUNT(*)::bigint").
		From("uv_service_change_event").
		Where("created_at >= ?", since).
		GroupBy("b")

	if kind != ChangeKindAny {
		q = q.Where(squirrel.Eq{"change_type": string(kind)})
	}

	query, args, err := q.ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build bucketed changes since query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query bucketed change events: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	return timeseries.ReadBucketMap(rows)
}

// StreamChangeEvents invokes fn for every change event of scanID in newest-
// first order. Returning an error from fn stops the iteration. Caller is
// responsible for output framing (e.g. CSV header / footer); the repo just
// hands over events one-by-one so the whole result set never materialises in
// memory.
func (p *PostgreSQL) StreamChangeEvents(ctx context.Context, scanID uint64, fn func(*ChangeEvent) error) error {
	query, args, err := sq.Select(
		"id", "scan_id", "host_id", "service_id", "previous_scan_id", "change_type", "details", "created_at",
	).
		From("uv_service_change_event").
		Where(squirrel.Eq{"scan_id": scanID}).
		OrderBy("id DESC").
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build stream change events query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't query delta events: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		event := &ChangeEvent{}

		var raw []byte

		if err := rows.Scan(
			&event.ID, &event.ScanID, &event.HostID, &event.ServiceID, &event.PreviousScanID,
			&event.ChangeType, &raw, &event.CreatedAt,
		); err != nil {
			return fmt.Errorf("can't scan delta event: %w", pgkit.Handle(err))
		}

		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &event.Details); err != nil {
				return fmt.Errorf("can't unmarshal change event details: %w", err)
			}
		}

		if err := fn(event); err != nil {
			return err
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("can't iterate delta events: %w", err)
	}

	return nil
}
