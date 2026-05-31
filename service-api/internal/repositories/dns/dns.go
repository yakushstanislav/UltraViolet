// Package dns stores forward DNS records resolved for discovered hosts.
package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Record is a single resolved DNS entry persisted for a host.
type Record struct {
	ID         uint64
	HostID     uint64
	RecordType string
	Name       string
	Value      string
	// Source is the provenance of the record: "ptr", "san", "ct" or "fcrdns".
	Source string
	// ForwardConfirmed is true when a PTR hostname forward-resolves back to the
	// scanned IP (forward-confirmed reverse DNS).
	ForwardConfirmed bool
	CapturedAt       time.Time
}

// Repository is the storage contract for DNS records.
type Repository interface {
	UpsertRecords(ctx context.Context, hostID uint64, records []Record) error
	ListByHostID(ctx context.Context, hostID uint64) ([]Record, error)
	// WithTx returns a Repository that routes every query through tx.
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

// UpsertRecords inserts or refreshes captured_at for each record.
// The unique constraint on (host_id, record_type, value) prevents duplicates.
// On conflict, captured_at and last_seen are bumped while first_seen is
// preserved to track historical DNS observations.
func (p *PostgreSQL) UpsertRecords(ctx context.Context, hostID uint64, records []Record) error {
	if len(records) == 0 {
		return nil
	}

	now := time.Now().UTC()

	qb := sq.Insert("uv_dns_record").
		Columns("host_id", "record_type", "name", "value", "source", "forward_confirmed", "captured_at", "first_seen", "last_seen")

	for _, r := range records {
		qb = qb.Values(hostID, r.RecordType, r.Name, r.Value, r.Source, r.ForwardConfirmed, now, now, now)
	}

	query, args, err := qb.
		Suffix(`ON CONFLICT (host_id, record_type, value) DO UPDATE SET
    captured_at       = EXCLUDED.captured_at,
    last_seen         = EXCLUDED.last_seen,
    source            = EXCLUDED.source,
    forward_confirmed = uv_dns_record.forward_confirmed OR EXCLUDED.forward_confirmed`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert dns records query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert dns records: %w", pgkit.Handle(err))
	}

	return nil
}

// ListByHostID returns all DNS records for the given host, ordered by type then value.
func (p *PostgreSQL) ListByHostID(ctx context.Context, hostID uint64) ([]Record, error) {
	query, args, err := sq.Select(
		"id", "host_id", "record_type", "name", "value", "source", "forward_confirmed", "captured_at",
	).
		From("uv_dns_record").
		Where(squirrel.Eq{"host_id": hostID}).
		OrderBy("record_type", "value").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list dns records query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't list dns records: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []Record

	for rows.Next() {
		var r Record

		if err := rows.Scan(
			&r.ID, &r.HostID, &r.RecordType, &r.Name, &r.Value, &r.Source, &r.ForwardConfirmed, &r.CapturedAt,
		); err != nil {
			return nil, fmt.Errorf("can't scan dns record: %w", pgkit.Handle(err))
		}

		out = append(out, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate dns records: %w", err)
	}

	return out, nil
}
