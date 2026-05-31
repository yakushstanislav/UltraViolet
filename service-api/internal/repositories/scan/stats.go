package scan

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/timeseries"
)

// StatusCounts holds per-status scan queue totals for the dashboard.
type StatusCounts struct {
	Pending uint64
	Running uint64
	Paused  uint64
	Done    uint64
	Failed  uint64
}

// CountStatusTotals returns scan counts grouped by status in one query.
func (p *PostgreSQL) CountStatusTotals(ctx context.Context) (StatusCounts, error) {
	query, args, err := sq.Select().
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE status = ?)", StatusPending)).
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE status = ?)", StatusRunning)).
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE status = ?)", StatusPaused)).
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE status = ?)", StatusDone)).
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE status = ?)", StatusFailed)).
		From("uv_scan").
		ToSql()
	if err != nil {
		return StatusCounts{}, fmt.Errorf("can't build count status totals query: %w", err)
	}

	var out StatusCounts

	if err := p.pool.QueryRow(ctx, query, args...).Scan(
		&out.Pending, &out.Running, &out.Paused, &out.Done, &out.Failed,
	); err != nil {
		return StatusCounts{}, fmt.Errorf("can't count scan status totals: %w", pgkit.Handle(err))
	}

	return out, nil
}

// CountByStatus returns the number of scans in the given status.
func (p *PostgreSQL) CountByStatus(ctx context.Context, status Status) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").From("uv_scan").Where(squirrel.Eq{"status": status}).ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count by status query: %w", err)
	}

	var n uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count scans: %w", pgkit.Handle(err))
	}

	return n, nil
}

// CountSince returns the number of scans whose created_at is at or after the given time.
func (p *PostgreSQL) CountSince(ctx context.Context, since time.Time) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").From("uv_scan").Where("created_at >= ?", since).ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count since query: %w", err)
	}

	var n uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count scans since: %w", pgkit.Handle(err))
	}

	return n, nil
}

// LastFinishedAt returns the most recent finished_at across scans that have
// reached a terminal outcome (DONE, FAILED, or CANCELED), matching how
// “recent scans” are listed on the dashboard.
func (p *PostgreSQL) LastFinishedAt(ctx context.Context) (sql.NullTime, error) {
	query, args, err := sq.Select("MAX(finished_at)").
		From("uv_scan").
		Where(squirrel.Eq{"status": []Status{StatusDone, StatusFailed, StatusCanceled}}).
		Where("finished_at IS NOT NULL").
		ToSql()
	if err != nil {
		return sql.NullTime{}, fmt.Errorf("can't build last finished at query: %w", err)
	}

	var last sql.NullTime

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&last); err != nil {
		return sql.NullTime{}, fmt.Errorf("can't fetch last finished scan: %w", pgkit.Handle(err))
	}

	return last, nil
}

// BucketedCreatedSince returns a histogram of scans created per bucket since
// the given time. Bucket must be "hour" or "day" (callers validate this).
func (p *PostgreSQL) BucketedCreatedSince(ctx context.Context, since time.Time, bucket string) (map[time.Time]uint64, error) {
	query, args, err := sq.Select().
		Column(squirrel.Expr("date_trunc(?, created_at) AS b", bucket)).
		Column("COUNT(*)::bigint").
		From("uv_scan").
		Where("created_at >= ?", since).
		GroupBy("b").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build bucketed created scans query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query bucketed created scans: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	return timeseries.ReadBucketMap(rows)
}

// BucketedCompletedSince returns a histogram of DONE scans grouped by
// finished_at per bucket since the given time.
func (p *PostgreSQL) BucketedCompletedSince(ctx context.Context, since time.Time, bucket string) (map[time.Time]uint64, error) {
	query, args, err := sq.Select().
		Column(squirrel.Expr("date_trunc(?, finished_at) AS b", bucket)).
		Column("COUNT(*)::bigint").
		From("uv_scan").
		Where(squirrel.Eq{"status": StatusDone}).
		Where("finished_at >= ?", since).
		GroupBy("b").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build bucketed completed scans query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query bucketed completed scans: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	return timeseries.ReadBucketMap(rows)
}

// DurationStats returns average and median duration across DONE scans whose
// started_at and finished_at are both populated.
func (p *PostgreSQL) DurationStats(ctx context.Context) (DurationStats, error) {
	query, args, err := sq.Select(
		"AVG(EXTRACT(EPOCH FROM (finished_at - started_at)))",
		"percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (finished_at - started_at)))",
		"COUNT(*)::bigint",
	).
		From("uv_scan").
		Where(squirrel.Eq{"status": StatusDone}).
		Where("started_at IS NOT NULL").
		Where("finished_at IS NOT NULL").
		ToSql()
	if err != nil {
		return DurationStats{}, fmt.Errorf("can't build duration stats query: %w", err)
	}

	var (
		avg    sql.NullFloat64
		median sql.NullFloat64
		sample int64
	)

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&avg, &median, &sample); err != nil {
		return DurationStats{}, fmt.Errorf("can't query duration stats: %w", pgkit.Handle(err))
	}

	if sample < 0 {
		sample = 0
	}

	out := DurationStats{Sample: uint64(sample)}

	if avg.Valid {
		out.AvgSec = avg.Float64
	}

	if median.Valid {
		out.MedianSec = median.Float64
	}

	return out, nil
}

// SuccessStatsSince returns DONE and FAILED counts for scans that finished at
// or after the given time.
func (p *PostgreSQL) SuccessStatsSince(ctx context.Context, since time.Time) (SuccessStats, error) {
	query, args, err := sq.Select().
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE status = ?)::bigint", StatusDone)).
		Column(squirrel.Expr("COUNT(*) FILTER (WHERE status = ?)::bigint", StatusFailed)).
		From("uv_scan").
		Where("finished_at IS NOT NULL").
		Where("finished_at >= ?", since).
		ToSql()
	if err != nil {
		return SuccessStats{}, fmt.Errorf("can't build success stats query: %w", err)
	}

	var (
		done   int64
		failed int64
	)

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&done, &failed); err != nil {
		return SuccessStats{}, fmt.Errorf("can't query success stats: %w", pgkit.Handle(err))
	}

	if done < 0 {
		done = 0
	}

	if failed < 0 {
		failed = 0
	}

	return SuccessStats{Done: uint64(done), Failed: uint64(failed)}, nil
}

// RecentWithDelta returns recently-terminated scans (DONE, FAILED or CANCELED)
// joined with their delta summary and snapshot count.
func (p *PostgreSQL) RecentWithDelta(ctx context.Context, limit uint64) ([]RecentScan, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select(
		"s.id", "s.name", "s.status", "s.started_at", "s.finished_at",
		"COALESCE(d.new_services, 0)",
		"COALESCE(d.disappeared_services, 0)",
		"COALESCE(d.changed_services, 0)",
		"COALESCE((SELECT COUNT(*) FROM uv_service_snapshot WHERE scan_id = s.id), 0)::bigint",
	).
		From("uv_scan s").
		LeftJoin("uv_scan_delta_summary d ON d.scan_id = s.id").
		Where(squirrel.Eq{"s.status": []Status{StatusDone, StatusFailed, StatusCanceled}}).
		OrderBy("COALESCE(s.finished_at, s.created_at) DESC", "s.id DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build recent with delta query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query recent scans: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []RecentScan

	for rows.Next() {
		var (
			row    RecentScan
			status string
			found  int64
		)

		if err := rows.Scan(
			&row.ID, &row.Name, &status, &row.StartedAt, &row.FinishedAt,
			&row.NewServices, &row.DisappearedServices, &row.ChangedServices,
			&found,
		); err != nil {
			return nil, fmt.Errorf("can't scan recent scan: %w", pgkit.Handle(err))
		}

		if found < 0 {
			found = 0
		}

		row.Status = Status(status)
		row.ServicesFound = uint64(found)

		out = append(out, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate recent scans: %w", err)
	}

	return out, nil
}
