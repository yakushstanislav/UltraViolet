package matchstate

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

// Repository tracks the last fingerprint hash matched per service.
type Repository interface {
	Upsert(ctx context.Context, serviceID uint64, fingerprintHash string, matchedAt time.Time) error
	Delete(ctx context.Context, serviceID uint64) error
	WithTx(tx pgx.Tx) Repository
}

// PostgreSQL implements Repository.
type PostgreSQL struct {
	db pgkit.Querier
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{db: pool}
}

// WithTx routes through tx.
func (p *PostgreSQL) WithTx(tx pgx.Tx) Repository {
	return &PostgreSQL{db: tx}
}

// Upsert records the fingerprint hash used for the latest match pass.
func (p *PostgreSQL) Upsert(ctx context.Context, serviceID uint64, fingerprintHash string, matchedAt time.Time) error {
	if matchedAt.IsZero() {
		matchedAt = time.Now().UTC()
	}

	query, args, err := sq.Insert("uv_service_match_state").
		Columns("service_id", "fingerprint_hash", "matched_at").
		Values(serviceID, fingerprintHash, matchedAt).
		Suffix(`ON CONFLICT (service_id) DO UPDATE SET
    fingerprint_hash = EXCLUDED.fingerprint_hash,
    matched_at       = EXCLUDED.matched_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert service match state query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert service match state: %w", pgkit.Handle(err))
	}

	return nil
}

// Delete removes match-state for a service (no fingerprint / reclassified).
func (p *PostgreSQL) Delete(ctx context.Context, serviceID uint64) error {
	query, args, err := sq.Delete("uv_service_match_state").
		Where(squirrel.Eq{"service_id": serviceID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build delete service match state query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't delete service match state: %w", pgkit.Handle(err))
	}

	return nil
}
