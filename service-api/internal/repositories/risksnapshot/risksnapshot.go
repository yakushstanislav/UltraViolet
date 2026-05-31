// Package risksnapshot persists uv_host_risk_snapshot and
// uv_service_risk_snapshot rows. Snapshots are append-only timelines so the
// dashboard can render trend lines and the alerting pipeline can detect
// score velocity.
package risksnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// ErrNotFound is returned when a snapshot lookup misses.
var ErrNotFound = pgkit.ErrNoRows

// HostSnapshot is one row of uv_host_risk_snapshot.
type HostSnapshot struct {
	HostID      uint64
	CapturedAt  time.Time
	Score       int32
	Probability float64
	Impact      float64
	Confidence  float64
	FactorsJSON []byte
}

// ServiceSnapshot is one row of uv_service_risk_snapshot.
type ServiceSnapshot struct {
	ServiceID   uint64
	CapturedAt  time.Time
	Score       int32
	Probability float64
	Confidence  float64
	FactorsJSON []byte
}

// Repository is the storage contract.
type Repository interface {
	AppendHost(ctx context.Context, snapshot HostSnapshot) error
	AppendService(ctx context.Context, snapshot ServiceSnapshot) error
	// LatestHost returns the most recent host snapshot, or ErrNotFound when
	// the timeline is empty.
	LatestHost(ctx context.Context, hostID uint64) (HostSnapshot, error)
	// ListHost returns snapshots in time order (oldest first) bounded by
	// since/until. The result is capped at limit rows.
	ListHost(ctx context.Context, hostID uint64, since, until time.Time, limit uint64) ([]HostSnapshot, error)
	// PruneOlderThan deletes host + service snapshots older than the
	// supplied cutoff and returns the count removed.
	PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	// WithTx returns a Repository that routes every query through tx.
	WithTx(tx pgx.Tx) Repository
}

// PostgreSQL is the pgx-backed Repository.
type PostgreSQL struct {
	db pgkit.Querier
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{db: pool}
}

// WithTx routes every query through tx.
func (p *PostgreSQL) WithTx(tx pgx.Tx) Repository {
	return &PostgreSQL{db: tx}
}

// AppendHost inserts one uv_host_risk_snapshot row. Conflicts on the
// (host_id, captured_at) PK are a no-op so retries are safe.
func (p *PostgreSQL) AppendHost(ctx context.Context, snapshot HostSnapshot) error {
	if snapshot.CapturedAt.IsZero() {
		snapshot.CapturedAt = time.Now().UTC()
	}

	factors := snapshot.FactorsJSON
	if factors == nil {
		factors = []byte("{}")
	}

	query, args, err := sq.Insert("uv_host_risk_snapshot").
		Columns("host_id", "captured_at", "score", "probability", "impact", "confidence", "risk_factors").
		Values(
			snapshot.HostID,
			snapshot.CapturedAt,
			snapshot.Score,
			snapshot.Probability,
			snapshot.Impact,
			snapshot.Confidence,
			squirrel.Expr("?::jsonb", string(factors)),
		).
		Suffix("ON CONFLICT (host_id, captured_at) DO NOTHING").
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build append host snapshot query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't append host snapshot: %w", pgkit.Handle(err))
	}

	return nil
}

// AppendService inserts one uv_service_risk_snapshot row.
func (p *PostgreSQL) AppendService(ctx context.Context, snapshot ServiceSnapshot) error {
	if snapshot.CapturedAt.IsZero() {
		snapshot.CapturedAt = time.Now().UTC()
	}

	factors := snapshot.FactorsJSON
	if factors == nil {
		factors = []byte("{}")
	}

	query, args, err := sq.Insert("uv_service_risk_snapshot").
		Columns("service_id", "captured_at", "score", "probability", "confidence", "risk_factors").
		Values(
			snapshot.ServiceID,
			snapshot.CapturedAt,
			snapshot.Score,
			snapshot.Probability,
			snapshot.Confidence,
			squirrel.Expr("?::jsonb", string(factors)),
		).
		Suffix("ON CONFLICT (service_id, captured_at) DO NOTHING").
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build append service snapshot query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't append service snapshot: %w", pgkit.Handle(err))
	}

	return nil
}

// LatestHost returns the most-recent snapshot for the host.
func (p *PostgreSQL) LatestHost(ctx context.Context, hostID uint64) (HostSnapshot, error) {
	query, args, err := sq.Select(
		"host_id", "captured_at", "score", "probability", "impact", "confidence", "risk_factors",
	).
		From("uv_host_risk_snapshot").
		Where(squirrel.Eq{"host_id": hostID}).
		OrderBy("captured_at DESC").
		Limit(1).
		ToSql()
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("can't build latest host snapshot query: %w", err)
	}

	var snapshot HostSnapshot

	if err := p.db.QueryRow(ctx, query, args...).Scan(
		&snapshot.HostID,
		&snapshot.CapturedAt,
		&snapshot.Score,
		&snapshot.Probability,
		&snapshot.Impact,
		&snapshot.Confidence,
		&snapshot.FactorsJSON,
	); err != nil {
		if errors.Is(err, pgkit.ErrNoRows) {
			return HostSnapshot{}, ErrNotFound
		}

		return HostSnapshot{}, fmt.Errorf("can't load latest host snapshot: %w", pgkit.Handle(err))
	}

	return snapshot, nil
}

// ListHost returns host snapshots in time order (oldest first).
func (p *PostgreSQL) ListHost(ctx context.Context, hostID uint64, since, until time.Time, limit uint64) ([]HostSnapshot, error) {
	if limit == 0 {
		limit = 1000
	}

	builder := sq.Select(
		"host_id", "captured_at", "score", "probability", "impact", "confidence", "risk_factors",
	).
		From("uv_host_risk_snapshot").
		Where(squirrel.Eq{"host_id": hostID})

	if !since.IsZero() {
		builder = builder.Where(squirrel.GtOrEq{"captured_at": since})
	}

	if !until.IsZero() {
		builder = builder.Where(squirrel.LtOrEq{"captured_at": until})
	}

	builder = builder.OrderBy("captured_at ASC").Limit(limit)

	query, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list host snapshots query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query host snapshots: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]HostSnapshot, 0, limit)

	for rows.Next() {
		var snapshot HostSnapshot

		if err := rows.Scan(
			&snapshot.HostID,
			&snapshot.CapturedAt,
			&snapshot.Score,
			&snapshot.Probability,
			&snapshot.Impact,
			&snapshot.Confidence,
			&snapshot.FactorsJSON,
		); err != nil {
			return nil, fmt.Errorf("can't scan host snapshot: %w", pgkit.Handle(err))
		}

		out = append(out, snapshot)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate host snapshots: %w", err)
	}

	return out, nil
}

// PruneOlderThan deletes host + service snapshots older than cutoff in one
// pass. Returns the total number of rows removed across both tables.
func (p *PostgreSQL) PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if cutoff.IsZero() {
		return 0, errors.New("can't prune snapshots: cutoff is zero")
	}

	hostSQL, hostArgs, err := sq.Delete("uv_host_risk_snapshot").
		Where(squirrel.Lt{"captured_at": cutoff}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build prune host snapshots query: %w", err)
	}

	hostTag, err := p.db.Exec(ctx, hostSQL, hostArgs...)
	if err != nil {
		return 0, fmt.Errorf("can't prune host snapshots: %w", pgkit.Handle(err))
	}

	serviceSQL, serviceArgs, err := sq.Delete("uv_service_risk_snapshot").
		Where(squirrel.Lt{"captured_at": cutoff}).
		ToSql()
	if err != nil {
		return hostTag.RowsAffected(), fmt.Errorf("can't build prune service snapshots query: %w", err)
	}

	serviceTag, err := p.db.Exec(ctx, serviceSQL, serviceArgs...)
	if err != nil {
		return hostTag.RowsAffected(), fmt.Errorf("can't prune service snapshots: %w", pgkit.Handle(err))
	}

	return hostTag.RowsAffected() + serviceTag.RowsAffected(), nil
}

// MarshalFactors is a convenience for callers that hold a typed factors
// struct and want to persist it without dragging encoding/json into their
// own imports.
func MarshalFactors(value any) ([]byte, error) {
	if value == nil {
		return []byte("{}"), nil
	}

	out, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("can't marshal risk factors: %w", err)
	}

	return out, nil
}
