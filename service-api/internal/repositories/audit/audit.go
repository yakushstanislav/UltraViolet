// Package audit stores per-request audit events for security review.
package audit

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

// Event is one persisted audit row.
type Event struct {
	ID         uint64
	UserID     sql.NullInt64
	ActorRole  sql.NullString
	ActorIP    sql.NullString
	Method     string
	Path       string
	StatusCode int
	ResourceID sql.NullString
	UserAgent  sql.NullString
	CreatedAt  time.Time
}

// ListFilter narrows the audit event listing. Empty / nil fields are ignored.
// StatusFamily is one of "2xx", "3xx", "4xx", "5xx" and bounds status_code.
// Query is matched case-insensitively against path, actor_ip and resource_id.
type ListFilter struct {
	Method       string
	StatusFamily string
	Query        string
	UserID       *uint64
	Since        *time.Time
	Until        *time.Time
}

// Repository describes the audit storage contract.
type Repository interface {
	Insert(ctx context.Context, event *Event) error
	List(ctx context.Context, filter ListFilter, limit, offset uint64) ([]*Event, uint64, error)
}

// PostgreSQL implements Repository.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

// Insert appends a single audit event.
func (p *PostgreSQL) Insert(ctx context.Context, event *Event) error {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}

	query, args, err := sq.Insert("uv_audit_event").
		Columns("user_id", "actor_role", "actor_ip", "method", "path", "status_code", "resource_id", "user_agent", "created_at").
		Values(
			event.UserID, event.ActorRole, event.ActorIP,
			event.Method, event.Path, event.StatusCode,
			event.ResourceID, event.UserAgent, event.CreatedAt,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build insert audit event query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't insert audit event: %w", pgkit.Handle(err))
	}

	return nil
}

// List returns a paginated newest-first list of audit events matching filter.
func (p *PostgreSQL) List(
	ctx context.Context,
	filter ListFilter,
	limit, offset uint64,
) ([]*Event, uint64, error) {
	if limit == 0 {
		limit = 100
	}

	where := buildAuditWhere(filter)

	countBuilder := sq.Select("COUNT(*)").From("uv_audit_event")
	if where != nil {
		countBuilder = countBuilder.Where(where)
	}

	countQuery, countArgs, err := countBuilder.ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count audit events query: %w", err)
	}

	var total uint64

	if err = p.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("can't count audit events: %w", pgkit.Handle(err))
	}

	listBuilder := sq.Select(
		"id", "user_id", "actor_role", "actor_ip", "method", "path",
		"status_code", "resource_id", "user_agent", "created_at",
	).
		From("uv_audit_event").
		OrderBy("id DESC").
		Limit(limit).
		Offset(offset)
	if where != nil {
		listBuilder = listBuilder.Where(where)
	}

	query, args, err := listBuilder.ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list audit events query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list audit events: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*Event

	for rows.Next() {
		event := &Event{}

		err := rows.Scan(
			&event.ID, &event.UserID, &event.ActorRole, &event.ActorIP,
			&event.Method, &event.Path, &event.StatusCode,
			&event.ResourceID, &event.UserAgent, &event.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("can't scan audit event: %w", pgkit.Handle(err))
		}

		out = append(out, event)
	}

	return out, total, rows.Err()
}

// buildAuditWhere assembles the WHERE clause shared by count and list queries.
// Returns nil when filter has no active predicates so callers can skip .Where.
func buildAuditWhere(filter ListFilter) squirrel.Sqlizer {
	clauses := squirrel.And{}

	if filter.Method != "" {
		clauses = append(clauses, squirrel.Eq{"method": filter.Method})
	}

	if low, high, ok := statusFamilyBounds(filter.StatusFamily); ok {
		clauses = append(
			clauses,
			squirrel.GtOrEq{"status_code": low},
			squirrel.Lt{"status_code": high},
		)
	}

	if filter.UserID != nil {
		clauses = append(clauses, squirrel.Eq{"user_id": *filter.UserID})
	}

	if filter.Since != nil {
		clauses = append(clauses, squirrel.GtOrEq{"created_at": *filter.Since})
	}

	if filter.Until != nil {
		clauses = append(clauses, squirrel.Lt{"created_at": *filter.Until})
	}

	if filter.Query != "" {
		pattern := "%" + filter.Query + "%"
		clauses = append(clauses, squirrel.Or{
			squirrel.ILike{"path": pattern},
			squirrel.ILike{"actor_ip": pattern},
			squirrel.ILike{"resource_id": pattern},
		})
	}

	if len(clauses) == 0 {
		return nil
	}

	return clauses
}

func statusFamilyBounds(family string) (int, int, bool) {
	switch family {
	case "2xx":
		return 200, 300, true
	case "3xx":
		return 300, 400, true
	case "4xx":
		return 400, 500, true
	case "5xx":
		return 500, 600, true
	default:
		return 0, 0, false
	}
}
