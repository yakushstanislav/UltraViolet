// Package riskpolicy persists the singleton uv_risk_policy row plus the
// per-protocol prior table that feed the v2 scoring model.
package riskpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// ErrNotFound is returned when a policy lookup misses.
var ErrNotFound = pgkit.ErrNoRows

const defaultPolicyName = "default"

// Repository describes the policy storage contract.
type Repository interface {
	// GetDefault returns the singleton "default" policy row.
	GetDefault(ctx context.Context) (risk.Policy, error)
	// ListProtocolPriors returns the full per-protocol prior table.
	ListProtocolPriors(ctx context.Context) (risk.PriorTable, error)
	// Update writes the supplied policy fields to the "default" row.
	Update(ctx context.Context, policy risk.Policy) error
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

// WithTx routes every query through tx.
func (p *PostgreSQL) WithTx(tx pgx.Tx) Repository {
	return &PostgreSQL{db: tx}
}

// GetDefault loads the "default" row from uv_risk_policy. If the row is
// missing (database before the v2 migration ran) the seed policy compiled
// into the binary is returned so the scorer still works.
func (p *PostgreSQL) GetDefault(ctx context.Context) (risk.Policy, error) {
	query, args, err := sq.Select(
		"k_coefficient",
		"weight_blast",
		"weight_lateral",
		"decay_kev_halflife_days",
		"decay_epss_halflife_days",
		"decay_recency_halflife_days",
		"decay_tls_halflife_days",
		"decay_kev_floor",
		"decay_epss_floor",
		"decay_recency_floor",
		"decay_tls_floor",
		"untagged_impact_baseline",
		"untagged_confidence_cap",
		"high_risk_threshold",
	).
		From("uv_risk_policy").
		Where(squirrel.Eq{"name": defaultPolicyName}).
		Limit(1).
		ToSql()
	if err != nil {
		return risk.Policy{}, fmt.Errorf("can't build get default policy query: %w", err)
	}

	var (
		policy                          risk.Policy
		kevHL, epssHL, recencyHL, tlsHL int
	)

	err = p.db.QueryRow(ctx, query, args...).Scan(
		&policy.KCoefficient,
		&policy.WeightBlast,
		&policy.WeightLateral,
		&kevHL,
		&epssHL,
		&recencyHL,
		&tlsHL,
		&policy.KEVFloor,
		&policy.EPSSFloor,
		&policy.RecencyFloor,
		&policy.TLSFloor,
		&policy.UntaggedImpactBaseline,
		&policy.UntaggedConfidenceCap,
		&policy.HighRiskThreshold,
	)
	if err != nil {
		if errors.Is(err, pgkit.ErrNoRows) {
			return risk.DefaultPolicy(), nil
		}

		return risk.Policy{}, fmt.Errorf("can't load default policy: %w", pgkit.Handle(err))
	}

	policy.KEVHalfLife = time.Duration(kevHL) * 24 * time.Hour
	policy.EPSSHalfLife = time.Duration(epssHL) * 24 * time.Hour
	policy.RecencyHalfLife = time.Duration(recencyHL) * 24 * time.Hour
	policy.TLSHalfLife = time.Duration(tlsHL) * 24 * time.Hour

	return policy, nil
}

// ListProtocolPriors loads the entire uv_risk_protocol_prior table into a
// risk.PriorTable. Empty result (pre-migration) returns the compiled-in
// defaults so the scorer keeps working.
func (p *PostgreSQL) ListProtocolPriors(ctx context.Context) (risk.PriorTable, error) {
	query, args, err := sq.Select(
		"port_bucket",
		"protocol_family",
		"p_exposure",
		"prior_alpha",
		"prior_beta",
	).
		From("uv_risk_protocol_prior").
		ToSql()
	if err != nil {
		return risk.PriorTable{}, fmt.Errorf("can't build list protocol priors query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return risk.PriorTable{}, fmt.Errorf("can't query protocol priors: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	entries := make([]risk.PriorEntry, 0, 8)

	for rows.Next() {
		var (
			entry       risk.PriorEntry
			bucket, fam string
		)

		if err := rows.Scan(&bucket, &fam, &entry.PExposure, &entry.PriorAlpha, &entry.PriorBeta); err != nil {
			return risk.PriorTable{}, fmt.Errorf("can't scan protocol prior: %w", pgkit.Handle(err))
		}

		entry.PortBucket = risk.PortBucket(bucket)
		entry.ProtocolFamily = risk.ProtocolFamily(fam)
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return risk.PriorTable{}, fmt.Errorf("can't iterate protocol priors: %w", err)
	}

	if len(entries) == 0 {
		return risk.DefaultPriors(), nil
	}

	return risk.NewPriorTable(entries), nil
}

// Update persists every tunable field on the default policy row. Callers
// should hold their own write lock if they want consistent reads.
func (p *PostgreSQL) Update(ctx context.Context, policy risk.Policy) error {
	query, args, err := sq.Update("uv_risk_policy").
		Set("k_coefficient", policy.KCoefficient).
		Set("weight_blast", policy.WeightBlast).
		Set("weight_lateral", policy.WeightLateral).
		Set("decay_kev_halflife_days", int(policy.KEVHalfLife/(24*time.Hour))).
		Set("decay_epss_halflife_days", int(policy.EPSSHalfLife/(24*time.Hour))).
		Set("decay_recency_halflife_days", int(policy.RecencyHalfLife/(24*time.Hour))).
		Set("decay_tls_halflife_days", int(policy.TLSHalfLife/(24*time.Hour))).
		Set("decay_kev_floor", policy.KEVFloor).
		Set("decay_epss_floor", policy.EPSSFloor).
		Set("decay_recency_floor", policy.RecencyFloor).
		Set("decay_tls_floor", policy.TLSFloor).
		Set("untagged_impact_baseline", policy.UntaggedImpactBaseline).
		Set("untagged_confidence_cap", policy.UntaggedConfidenceCap).
		Set("high_risk_threshold", policy.HighRiskThreshold).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"name": defaultPolicyName}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update policy query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update default policy: %w", pgkit.Handle(err))
	}

	return nil
}
