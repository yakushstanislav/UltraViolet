// Package remediation persists the ordered list of operator actions the risk
// service believes would reduce a host's score the most.
package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// ErrNotFound is returned when a recommendation lookup misses.
var ErrNotFound = pgkit.ErrNoRows

// Recommendation is one row of uv_remediation_recommendation.
type Recommendation struct {
	ID                 int64
	HostID             uint64
	ServiceID          *uint64
	ActionCode         string
	Label              string
	ExpectedDeltaP     float64
	ExpectedDeltaScore int32
	Evidence           json.RawMessage
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Repository describes recommendation storage.
type Repository interface {
	ReplaceForHost(ctx context.Context, hostID uint64, recommendations []Recommendation) error
	TopForHost(ctx context.Context, hostID, limit uint64) ([]Recommendation, error)
	CountOpen(ctx context.Context) (int64, error)
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

// ReplaceForHost atomically clears every recommendation for the host and
// inserts the supplied set in one transaction. Recommendations are fully
// recomputed on every risk refresh, so there is no status to preserve.
func (p *PostgreSQL) ReplaceForHost(ctx context.Context, hostID uint64, recommendations []Recommendation) error {
	deleteSQL, deleteArgs, err := sq.Delete("uv_remediation_recommendation").
		Where(squirrel.Eq{"host_id": hostID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build clear recommendations query: %w", err)
	}

	if _, execErr := p.db.Exec(ctx, deleteSQL, deleteArgs...); execErr != nil {
		return fmt.Errorf("can't clear recommendations: %w", pgkit.Handle(execErr))
	}

	if len(recommendations) == 0 {
		return nil
	}

	builder := sq.Insert("uv_remediation_recommendation").
		Columns("host_id", "service_id", "action_code", "label", "expected_delta_p", "expected_delta_score", "evidence")

	for _, rec := range recommendations {
		evidence := rec.Evidence
		if len(evidence) == 0 {
			evidence = json.RawMessage(`{}`)
		}

		builder = builder.Values(
			hostID,
			rec.ServiceID,
			rec.ActionCode,
			rec.Label,
			rec.ExpectedDeltaP,
			rec.ExpectedDeltaScore,
			squirrel.Expr("?::jsonb", string(evidence)),
		)
	}

	insertSQL, insertArgs, err := builder.ToSql()
	if err != nil {
		return fmt.Errorf("can't build insert recommendations query: %w", err)
	}

	if _, err := p.db.Exec(ctx, insertSQL, insertArgs...); err != nil {
		return fmt.Errorf("can't insert recommendations: %w", pgkit.Handle(err))
	}

	return nil
}

// TopForHost returns recommendations ordered by expected score reduction.
func (p *PostgreSQL) TopForHost(ctx context.Context, hostID, limit uint64) ([]Recommendation, error) {
	if limit == 0 {
		limit = 20
	}

	query, args, err := sq.Select(
		"id", "host_id", "service_id", "action_code", "label",
		"expected_delta_p", "expected_delta_score", "evidence", "created_at", "updated_at",
	).
		From("uv_remediation_recommendation").
		Where(squirrel.Eq{"host_id": hostID}).
		OrderBy("expected_delta_score DESC", "id ASC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top recommendations query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top recommendations: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]Recommendation, 0, limit)

	for rows.Next() {
		var rec Recommendation

		if err := rows.Scan(
			&rec.ID,
			&rec.HostID,
			&rec.ServiceID,
			&rec.ActionCode,
			&rec.Label,
			&rec.ExpectedDeltaP,
			&rec.ExpectedDeltaScore,
			&rec.Evidence,
			&rec.CreatedAt,
			&rec.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("can't scan recommendation: %w", pgkit.Handle(err))
		}

		out = append(out, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate recommendations: %w", err)
	}

	return out, nil
}

// CountOpen returns the current count of recommendations across the entire
// inventory. Used by the Prometheus gauge sampler so dashboards can alert on
// remediation backlog growth.
func (p *PostgreSQL) CountOpen(ctx context.Context) (int64, error) {
	query, args, err := sq.Select("COUNT(*)::bigint").
		From("uv_remediation_recommendation").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count recommendations query: %w", err)
	}

	var count int64

	if err := p.db.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("can't count recommendations: %w", pgkit.Handle(err))
	}

	return count, nil
}
