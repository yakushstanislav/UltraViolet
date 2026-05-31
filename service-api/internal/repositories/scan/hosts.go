package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

// RecentScannedHost is one row in the recent-hosts table on scan detail.
type RecentScannedHost struct {
	HostID    uint64
	IP        string
	ScannedAt time.Time
}

// DistinctHostsScanned counts unique hosts with at least one open-port snapshot.
func (p *PostgreSQL) DistinctHostsScanned(ctx context.Context, scanID uint64) (uint64, error) {
	query, args, err := sq.Select("COUNT(DISTINCT host_id)").
		From("uv_service_snapshot").
		Where(squirrel.Eq{"scan_id": scanID}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build distinct hosts scanned query: %w", err)
	}

	var n uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count distinct hosts scanned: %w", pgkit.Handle(err))
	}

	return n, nil
}

// RecentScannedHosts returns the most recently snapshotted hosts for a scan.
func (p *PostgreSQL) RecentScannedHosts(ctx context.Context, scanID, limit uint64) ([]RecentScannedHost, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select("s.host_id", "s.ip::text", "s.created_at").
		From("uv_service_snapshot s").
		Where(squirrel.Eq{"s.scan_id": scanID}).
		Where(squirrel.Expr(
			"s.service_id IN (SELECT MIN(service_id) FROM uv_service_snapshot WHERE scan_id = ? GROUP BY host_id)",
			scanID,
		)).
		OrderBy("s.created_at DESC", "s.service_id DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build recent scanned hosts query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query recent scanned hosts: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []RecentScannedHost

	for rows.Next() {
		var row RecentScannedHost

		if err := rows.Scan(&row.HostID, &row.IP, &row.ScannedAt); err != nil {
			return nil, fmt.Errorf("can't scan recent host row: %w", pgkit.Handle(err))
		}

		out = append(out, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate recent scanned hosts: %w", err)
	}

	return out, nil
}
