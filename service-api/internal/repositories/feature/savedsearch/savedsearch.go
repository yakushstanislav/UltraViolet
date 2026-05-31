// Package savedsearch stores user-defined named search queries.
package savedsearch

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// SavedSearch is one row from uv_saved_search.
type SavedSearch struct {
	ID        uint64
	Name      string
	Query     map[string]any
	CreatedAt time.Time
	UpdatedAt time.Time
	LastRunAt sql.NullTime
}

// Repository is the storage contract for saved searches.
type Repository interface {
	Create(ctx context.Context, name string, query map[string]any) (uint64, error)
	Get(ctx context.Context, id uint64) (*SavedSearch, error)
	Delete(ctx context.Context, id uint64) error
	MarkRun(ctx context.Context, id uint64) error
	GetAll(ctx context.Context, limit, offset uint64) ([]*SavedSearch, uint64, error)
	Count(ctx context.Context) (uint64, error)
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

// Create inserts a new saved search and returns its id.
func (p *PostgreSQL) Create(ctx context.Context, name string, query map[string]any) (uint64, error) {
	payload, err := json.Marshal(query)
	if err != nil {
		return 0, fmt.Errorf("can't marshal saved search query: %w", err)
	}

	now := time.Now().UTC()

	buildSQL, args, err := sq.Insert("uv_saved_search").
		Columns("name", "query", "created_at", "updated_at").
		Values(name, payload, now, now).
		Suffix("RETURNING id").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build create saved search query: %w", err)
	}

	var id uint64

	if err := p.pool.QueryRow(ctx, buildSQL, args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("can't create saved search: %w", pgkit.Handle(err))
	}

	return id, nil
}

// GetAll returns a paginated list of saved searches and the total count.
func (p *PostgreSQL) GetAll(ctx context.Context, limit, offset uint64) ([]*SavedSearch, uint64, error) {
	countSQL, countArgs, err := sq.Select("COUNT(*)").From("uv_saved_search").ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count saved searches query: %w", err)
	}

	var total uint64

	err = p.pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("can't count saved searches: %w", pgkit.Handle(err))
	}

	query, args, err := sq.Select("id", "name", "query", "created_at", "updated_at", "last_run_at").
		From("uv_saved_search").
		OrderBy("id DESC").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list saved searches query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list saved searches: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*SavedSearch

	for rows.Next() {
		item := &SavedSearch{}

		var raw []byte

		if err := rows.Scan(&item.ID, &item.Name, &raw, &item.CreatedAt, &item.UpdatedAt, &item.LastRunAt); err != nil {
			return nil, 0, fmt.Errorf("can't scan saved search: %w", pgkit.Handle(err))
		}

		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &item.Query); err != nil {
				return nil, 0, fmt.Errorf("can't unmarshal saved search query: %w", err)
			}
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate saved searches: %w", err)
	}

	return out, total, nil
}

// Count returns the total number of saved searches.
func (p *PostgreSQL) Count(ctx context.Context) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").From("uv_saved_search").ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count saved searches query: %w", err)
	}

	var n uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count saved searches: %w", pgkit.Handle(err))
	}

	return n, nil
}

// Get returns one saved search by id.
func (p *PostgreSQL) Get(ctx context.Context, id uint64) (*SavedSearch, error) {
	query, args, err := sq.Select("id", "name", "query", "created_at", "updated_at", "last_run_at").
		From("uv_saved_search").
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get saved search query: %w", err)
	}

	item := &SavedSearch{}

	var raw []byte

	err = p.pool.QueryRow(ctx, query, args...).Scan(
		&item.ID, &item.Name, &raw, &item.CreatedAt, &item.UpdatedAt, &item.LastRunAt,
	)
	if err != nil {
		return nil, fmt.Errorf("can't get saved search: %w", pgkit.Handle(err))
	}

	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &item.Query); err != nil {
			return nil, fmt.Errorf("can't unmarshal saved search query: %w", err)
		}
	}

	return item, nil
}

// Delete removes a saved search. Returns pgkit.ErrNoRows when no row matched.
func (p *PostgreSQL) Delete(ctx context.Context, id uint64) error {
	query, args, err := sq.Delete("uv_saved_search").
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build delete saved search query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't delete saved search: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return pgkit.ErrNoRows
	}

	return nil
}

// MarkRun updates last_run_at to now. Missing rows are not an error here:
// MarkRun is a side-effect of running a search, not a state assertion.
func (p *PostgreSQL) MarkRun(ctx context.Context, id uint64) error {
	query, args, err := sq.Update("uv_saved_search").
		Set("last_run_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build mark run saved search query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't mark saved search run: %w", pgkit.Handle(err))
	}

	return nil
}
