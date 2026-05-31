package syncstate

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// SyncState mirrors the single row of uv_cve_sync_state.
type SyncState struct {
	LastModStart   sql.NullTime
	BootstrappedAt sql.NullTime
	UpdatedAt      time.Time
	EntriesTotal   sql.NullInt32
	EntriesDone    sql.NullInt32
}

// Repository tracks the NVD pagination checkpoint.
type Repository interface {
	Get(ctx context.Context) (*SyncState, error)
	MarkBootstrapped(ctx context.Context, at time.Time) error
	SetLastModStart(ctx context.Context, at time.Time) error
	SetEntries(ctx context.Context, total, done int) error
}

// PostgreSQL implements Repository.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

// Get returns the row, creating the singleton if missing.
func (p *PostgreSQL) Get(ctx context.Context) (*SyncState, error) {
	seedQuery, seedArgs, err := sq.Insert("uv_cve_sync_state").
		Columns("id").
		Values(1).
		Suffix("ON CONFLICT DO NOTHING").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build seed cve sync state query: %w", err)
	}

	if _, execErr := p.pool.Exec(ctx, seedQuery, seedArgs...); execErr != nil {
		return nil, fmt.Errorf("can't seed cve sync state: %w", pgkit.Handle(execErr))
	}

	selectQuery, selectArgs, err := sq.Select(
		"last_mod_start", "bootstrapped_at", "updated_at",
		"entries_total", "entries_done",
	).
		From("uv_cve_sync_state").
		Where(squirrel.Eq{"id": 1}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build read cve sync state query: %w", err)
	}

	var state SyncState
	if err := p.pool.QueryRow(ctx, selectQuery, selectArgs...).Scan(
		&state.LastModStart, &state.BootstrappedAt, &state.UpdatedAt,
		&state.EntriesTotal, &state.EntriesDone,
	); err != nil {
		return nil, fmt.Errorf("can't read cve sync state: %w", pgkit.Handle(err))
	}

	return &state, nil
}

// SetEntries records the catalog-wide totals used by the progress bar. Pass
// -1 for "leave unchanged".
func (p *PostgreSQL) SetEntries(ctx context.Context, total, done int) error {
	upd := sq.Update("uv_cve_sync_state").
		Set("updated_at", squirrel.Expr("NOW()")).
		Where(squirrel.Eq{"id": 1})

	if total >= 0 {
		upd = upd.Set("entries_total", total)
	}

	if done >= 0 {
		upd = upd.Set("entries_done", done)
	}

	query, args, err := upd.ToSql()
	if err != nil {
		return fmt.Errorf("can't build set entries query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update entries counters: %w", pgkit.Handle(err))
	}

	return nil
}

// MarkBootstrapped sets the bootstrapped_at timestamp.
func (p *PostgreSQL) MarkBootstrapped(ctx context.Context, at time.Time) error {
	query, args, err := sq.Update("uv_cve_sync_state").
		Set("bootstrapped_at", at).
		Set("updated_at", squirrel.Expr("NOW()")).
		Where(squirrel.Eq{"id": 1}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build bootstrapped_at query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update bootstrapped_at: %w", pgkit.Handle(err))
	}

	return nil
}

// SetLastModStart advances the incremental sync cursor.
func (p *PostgreSQL) SetLastModStart(ctx context.Context, at time.Time) error {
	query, args, err := sq.Update("uv_cve_sync_state").
		Set("last_mod_start", at).
		Set("updated_at", squirrel.Expr("NOW()")).
		Where(squirrel.Eq{"id": 1}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build last_mod_start query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update last_mod_start: %w", pgkit.Handle(err))
	}

	return nil
}
