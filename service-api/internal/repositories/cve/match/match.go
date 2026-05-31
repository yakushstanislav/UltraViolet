package match

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Match is one persisted (service, CVE) link.
//
// EPSSPercentile is in-memory only — it rides with the struct from the catalog
// through riskFromMatches but is not stored on uv_service_cve.
type Match struct {
	ServiceID      uint64
	CVEID          string
	MatchedVersion sql.NullString
	Severity       sql.NullString
	CVSSScore      sql.NullFloat64
	Confidence     int16
	MatchedAt      time.Time
	KEVAddedAt     sql.NullTime
	EPSSScore      sql.NullFloat64
	EPSSPercentile sql.NullFloat64
}

// Detail is Match enriched with the catalog summary, used by handlers.
type Detail struct {
	Match
	Summary    sql.NullString
	References []string
}

// SeverityCounts holds counts per CVSS severity bucket for a service or set.
type SeverityCounts struct {
	Critical uint64
	High     uint64
	Medium   uint64
	Low      uint64
}

// TopCVE is a row of "most prevalent CVE across the inventory".
type TopCVE struct {
	CVEID    string
	Severity sql.NullString
	Score    sql.NullFloat64
	Summary  sql.NullString
	Services uint64
}

// Repository describes per-service CVE persistence.
type Repository interface {
	ReplaceForService(ctx context.Context, serviceID uint64, matches []Match) error
	ListByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64][]Detail, error)
	CountsByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]SeverityCounts, error)
	GlobalCounts(ctx context.Context) (SeverityCounts, error)
	TopCVEs(ctx context.Context, limit uint64) ([]TopCVE, error)
	HostsWithSeverityAtLeast(ctx context.Context, severity string) (uint64, error)
	ServiceIDsWithSeverity(ctx context.Context, severities []string) ([]uint64, error)
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

// ReplaceForService deletes and re-inserts all matches for a service so the
// caller doesn't need to compute set differences.
//
// DELETE + INSERT must run atomically: a failure between them leaves the
// service showing no matches until the next probe re-runs. When bound to a
// pool we open our own transaction; when bound to an outer tx (WithTx) we
// reuse it so the outer caller stays in control of commit/rollback.
func (p *PostgreSQL) ReplaceForService(ctx context.Context, serviceID uint64, matches []Match) error {
	if tx, ok := p.db.(pgx.Tx); ok {
		return replaceForServiceTx(ctx, tx, serviceID, matches)
	}

	pool, ok := p.db.(*pgxpool.Pool)
	if !ok {
		return replaceForServiceTx(ctx, p.db, serviceID, matches)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can't begin replace service cve tx: %w", pgkit.Handle(err))
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if err := replaceForServiceTx(ctx, tx, serviceID, matches); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("can't commit replace service cve tx: %w", pgkit.Handle(err))
	}

	return nil
}

func replaceForServiceTx(ctx context.Context, q pgkit.Querier, serviceID uint64, matches []Match) error {
	deleteQuery, deleteArgs, err := sq.Delete("uv_service_cve").
		Where(squirrel.Eq{"service_id": serviceID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build delete service cve query: %w", err)
	}

	if _, execErr := q.Exec(ctx, deleteQuery, deleteArgs...); execErr != nil {
		return fmt.Errorf("can't clear service cve matches: %w", pgkit.Handle(execErr))
	}

	if len(matches) == 0 {
		return nil
	}

	now := time.Now().UTC()

	insert := sq.Insert("uv_service_cve").Columns(
		"service_id", "cve_id", "matched_version", "severity", "cvss_score", "confidence", "matched_at",
		"kev_added_at", "epss_score",
	)

	for _, match := range matches {
		matchedAt := match.MatchedAt
		if matchedAt.IsZero() {
			matchedAt = now
		}

		confidence := match.Confidence
		if confidence <= 0 {
			confidence = 60
		}

		insert = insert.Values(
			serviceID, match.CVEID, match.MatchedVersion,
			match.Severity, match.CVSSScore, confidence, matchedAt,
			match.KEVAddedAt, match.EPSSScore,
		)
	}

	query, args, err := insert.ToSql()
	if err != nil {
		return fmt.Errorf("can't build insert service cve query: %w", err)
	}

	if _, err := q.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't insert service cve matches: %w", pgkit.Handle(err))
	}

	return nil
}

// ListByServiceIDs returns matches grouped by service for the supplied ids.
func (p *PostgreSQL) ListByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64][]Detail, error) {
	out := make(map[uint64][]Detail, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(
		"m.service_id", "m.cve_id", "m.matched_version", "m.severity",
		"m.cvss_score", "m.confidence", "m.matched_at", "c.summary",
	).
		From("uv_service_cve m").
		LeftJoin("uv_cve c ON c.id = m.cve_id").
		Where("m.service_id = ANY(?)", serviceIDs).
		OrderBy("m.cvss_score DESC NULLS LAST", "m.cve_id ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list service cve query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query service cves: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var detail Detail

		err := rows.Scan(
			&detail.ServiceID, &detail.CVEID, &detail.MatchedVersion,
			&detail.Severity, &detail.CVSSScore, &detail.Confidence, &detail.MatchedAt,
			&detail.Summary,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan service cve: %w", pgkit.Handle(err))
		}

		out[detail.ServiceID] = append(out[detail.ServiceID], detail)
	}

	return out, rows.Err()
}

// CountsByServiceIDs returns the severity histogram per service.
func (p *PostgreSQL) CountsByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]SeverityCounts, error) {
	out := make(map[uint64]SeverityCounts, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(
		"service_id",
		"COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical",
		"COUNT(*) FILTER (WHERE severity = 'HIGH')     AS high",
		"COUNT(*) FILTER (WHERE severity = 'MEDIUM')   AS medium",
		"COUNT(*) FILTER (WHERE severity = 'LOW')      AS low",
	).
		From("uv_service_cve").
		Where("service_id = ANY(?)", serviceIDs).
		GroupBy("service_id").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build service cve counts query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query service cve counts: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var (
			id     uint64
			counts SeverityCounts
		)

		if err := rows.Scan(&id, &counts.Critical, &counts.High, &counts.Medium, &counts.Low); err != nil {
			return nil, fmt.Errorf("can't scan service cve count: %w", pgkit.Handle(err))
		}

		out[id] = counts
	}

	return out, rows.Err()
}

// GlobalCounts returns the dataset-wide severity histogram.
func (p *PostgreSQL) GlobalCounts(ctx context.Context) (SeverityCounts, error) {
	query, args, err := sq.Select(
		"COUNT(*) FILTER (WHERE severity = 'CRITICAL')",
		"COUNT(*) FILTER (WHERE severity = 'HIGH')",
		"COUNT(*) FILTER (WHERE severity = 'MEDIUM')",
		"COUNT(*) FILTER (WHERE severity = 'LOW')",
	).
		From("uv_service_cve").
		ToSql()
	if err != nil {
		return SeverityCounts{}, fmt.Errorf("can't build global cve counts query: %w", err)
	}

	var counts SeverityCounts
	if err := p.db.QueryRow(ctx, query, args...).Scan(
		&counts.Critical, &counts.High, &counts.Medium, &counts.Low,
	); err != nil {
		return SeverityCounts{}, fmt.Errorf("can't query global cve counts: %w", pgkit.Handle(err))
	}

	return counts, nil
}

// TopCVEs returns the most impactful CVE IDs across the inventory: highest
// severity first, then most recent (by NVD published_at), then largest blast
// radius. This is what the dashboard widget surfaces, so the ordering must
// match a security analyst's reading order — newly published criticals
// outrank old highs even if the latter cover more services.
func (p *PostgreSQL) TopCVEs(ctx context.Context, limit uint64) ([]TopCVE, error) {
	if limit == 0 {
		limit = 10
	}

	const severityRank = `CASE c.cvss_v3_severity
        WHEN 'CRITICAL' THEN 4
        WHEN 'HIGH'     THEN 3
        WHEN 'MEDIUM'   THEN 2
        WHEN 'LOW'      THEN 1
        ELSE 0
    END`

	// Primary key (service_id, cve_id) makes COUNT(*) equivalent to distinct
	// services per CVE. Aggregate first, then join uv_cve for ordering — avoids
	// scanning the full match table with GROUP BY on catalog columns.
	byCVE := sq.Select("cve_id", "COUNT(*)::bigint AS services").
		From("uv_service_cve").
		GroupBy("cve_id")

	query, args, err := sq.Select(
		"a.cve_id",
		"c.cvss_v3_severity",
		"c.cvss_v3_score",
		"c.summary",
		"a.services",
	).
		FromSelect(byCVE, "a").
		LeftJoin("uv_cve c ON c.id = a.cve_id").
		OrderBy(
			severityRank+" DESC",
			"c.cvss_v3_score DESC NULLS LAST",
			"c.published_at DESC NULLS LAST",
			"a.services DESC",
			"a.cve_id",
		).
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top cves query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top cves: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]TopCVE, 0, limit)

	for rows.Next() {
		var row TopCVE

		if err := rows.Scan(&row.CVEID, &row.Severity, &row.Score, &row.Summary, &row.Services); err != nil {
			return nil, fmt.Errorf("can't scan top cve: %w", pgkit.Handle(err))
		}

		out = append(out, row)
	}

	return out, rows.Err()
}

// HostsWithSeverityAtLeast counts distinct hosts that own a service with a
// match equal to or above the requested severity tier.
func (p *PostgreSQL) HostsWithSeverityAtLeast(ctx context.Context, severity string) (uint64, error) {
	if severity == "" {
		severity = "CRITICAL"
	}

	tier := severityTier(severity)

	q := sq.Select("COUNT(DISTINCT s.host_id)").
		From("uv_service_cve m").
		Join("uv_service s ON s.id = m.service_id")

	if severities := severitiesAtLeastTier(tier); len(severities) > 0 {
		q = q.Where("m.severity = ANY(?)", severities)
	}

	query, args, err := q.ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build hosts-with-severity query: %w", err)
	}

	var count uint64
	if err := p.db.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("can't count hosts with severity: %w", pgkit.Handle(err))
	}

	return count, nil
}

// ServiceIDsWithSeverity returns ids of services that own a match in the
// requested severity set. Empty input returns nil (no filter applied).
func (p *PostgreSQL) ServiceIDsWithSeverity(ctx context.Context, severities []string) ([]uint64, error) {
	if len(severities) == 0 {
		return nil, nil
	}

	query, args, err := sq.Select("DISTINCT service_id").
		From("uv_service_cve").
		Where("severity = ANY(?)", severities).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build service ids by severity query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query service ids by severity: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]uint64, 0, 64)

	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("can't scan service id: %w", pgkit.Handle(err))
		}

		out = append(out, id)
	}

	return out, rows.Err()
}

func severityTier(severity string) int {
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// severitiesAtLeastTier lists match severities at or above the numeric tier.
// Tier 0 means no severity filter (matches the old CASE >= 0 behaviour).
func severitiesAtLeastTier(tier int) []string {
	switch {
	case tier >= 4:
		return []string{"CRITICAL"}
	case tier == 3:
		return []string{"CRITICAL", "HIGH"}
	case tier == 2:
		return []string{"CRITICAL", "HIGH", "MEDIUM"}
	case tier == 1:
		return []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	default:
		return nil
	}
}
