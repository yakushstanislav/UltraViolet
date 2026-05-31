// Package attackpath stores the per-host centrality + pivot scores
// materialised by the attackpath worker. The risk scorer reads these rows to
// fuel the network_position probability channel; the /v1/attack-paths/{ip}
// endpoint exposes them to the UI.
package attackpath

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

// ErrNotFound is returned when an attack-path lookup misses.
var ErrNotFound = pgkit.ErrNoRows

// Score is one row of uv_host_attack_path_score.
type Score struct {
	HostID                 uint64
	Centrality             float64
	PivotScore             float64
	ReachableCriticalCount int32
	TopPathsJSON           json.RawMessage
	ComputedAt             time.Time
}

// Relation is one row of uv_host_relation.
type Relation struct {
	SrcHostID    uint64
	DstHostID    uint64
	RelationType string
	Strength     float64
	EvidenceJSON json.RawMessage
	ComputedAt   time.Time
}

// Repository describes attack-path storage.
type Repository interface {
	UpsertScore(ctx context.Context, score Score) error
	GetScore(ctx context.Context, hostID uint64) (Score, error)
	UpsertRelation(ctx context.Context, relation Relation) error
	ListRelationsForHost(ctx context.Context, hostID uint64) ([]Relation, error)
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

// UpsertScore writes (or updates) the centrality row for a host.
func (p *PostgreSQL) UpsertScore(ctx context.Context, score Score) error {
	if score.ComputedAt.IsZero() {
		score.ComputedAt = time.Now().UTC()
	}

	paths := score.TopPathsJSON
	if len(paths) == 0 {
		paths = json.RawMessage(`[]`)
	}

	query, args, err := sq.Insert("uv_host_attack_path_score").
		Columns("host_id", "centrality", "pivot_score", "reachable_critical_count", "top_paths", "computed_at").
		Values(
			score.HostID,
			score.Centrality,
			score.PivotScore,
			score.ReachableCriticalCount,
			squirrel.Expr("?::jsonb", string(paths)),
			score.ComputedAt,
		).
		Suffix(`ON CONFLICT (host_id) DO UPDATE SET
    centrality               = EXCLUDED.centrality,
    pivot_score              = EXCLUDED.pivot_score,
    reachable_critical_count = EXCLUDED.reachable_critical_count,
    top_paths                = EXCLUDED.top_paths,
    computed_at              = EXCLUDED.computed_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert attack path score query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert attack path score: %w", pgkit.Handle(err))
	}

	return nil
}

// GetScore returns one host's attack-path row or ErrNotFound.
func (p *PostgreSQL) GetScore(ctx context.Context, hostID uint64) (Score, error) {
	query, args, err := sq.Select("host_id", "centrality", "pivot_score", "reachable_critical_count", "top_paths", "computed_at").
		From("uv_host_attack_path_score").
		Where(squirrel.Eq{"host_id": hostID}).
		Limit(1).
		ToSql()
	if err != nil {
		return Score{}, fmt.Errorf("can't build get attack path score query: %w", err)
	}

	var score Score

	if err := p.db.QueryRow(ctx, query, args...).Scan(
		&score.HostID,
		&score.Centrality,
		&score.PivotScore,
		&score.ReachableCriticalCount,
		&score.TopPathsJSON,
		&score.ComputedAt,
	); err != nil {
		if errors.Is(err, pgkit.ErrNoRows) {
			return Score{}, ErrNotFound
		}

		return Score{}, fmt.Errorf("can't load attack path score: %w", pgkit.Handle(err))
	}

	return score, nil
}

// UpsertRelation persists one symmetric/directed relation edge.
func (p *PostgreSQL) UpsertRelation(ctx context.Context, relation Relation) error {
	if relation.ComputedAt.IsZero() {
		relation.ComputedAt = time.Now().UTC()
	}

	evidence := relation.EvidenceJSON
	if len(evidence) == 0 {
		evidence = json.RawMessage(`{}`)
	}

	query, args, err := sq.Insert("uv_host_relation").
		Columns("src_host_id", "dst_host_id", "relation_type", "strength", "evidence", "computed_at").
		Values(
			relation.SrcHostID,
			relation.DstHostID,
			relation.RelationType,
			relation.Strength,
			squirrel.Expr("?::jsonb", string(evidence)),
			relation.ComputedAt,
		).
		Suffix(`ON CONFLICT (src_host_id, dst_host_id, relation_type) DO UPDATE SET
    strength    = EXCLUDED.strength,
    evidence    = EXCLUDED.evidence,
    computed_at = EXCLUDED.computed_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert host relation query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert host relation: %w", pgkit.Handle(err))
	}

	return nil
}

// ListRelationsForHost returns every relation whose src or dst is hostID.
func (p *PostgreSQL) ListRelationsForHost(ctx context.Context, hostID uint64) ([]Relation, error) {
	query, args, err := sq.Select("src_host_id", "dst_host_id", "relation_type", "strength", "evidence", "computed_at").
		From("uv_host_relation").
		Where(squirrel.Or{
			squirrel.Eq{"src_host_id": hostID},
			squirrel.Eq{"dst_host_id": hostID},
		}).
		OrderBy("strength DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list host relations query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query host relations: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]Relation, 0, 8)

	for rows.Next() {
		var relation Relation

		if err := rows.Scan(
			&relation.SrcHostID,
			&relation.DstHostID,
			&relation.RelationType,
			&relation.Strength,
			&relation.EvidenceJSON,
			&relation.ComputedAt,
		); err != nil {
			return nil, fmt.Errorf("can't scan host relation: %w", pgkit.Handle(err))
		}

		out = append(out, relation)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate host relations: %w", err)
	}

	return out, nil
}
