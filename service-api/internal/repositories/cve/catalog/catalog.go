// Package catalog stores the local mirror of the NVD CVE catalog.
package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// cpeLeafInsertBatchRows caps how many CPE rows go into one INSERT. Each row
// contributes 13 bind parameters; PostgreSQL's extended-query protocol rejects
// more than 65535 parameters per statement (observed when a single CVE ships
// tens of thousands of CPE applicability leaves from NVD).
const cpeLeafInsertBatchRows = 3000

// ErrNotFound is returned when a CVE lookup misses.
var ErrNotFound = pgkit.ErrNoRows

// CVE is one persisted catalog row.
type CVE struct {
	ID                 string
	Source             string
	Summary            sql.NullString
	CVSSv3Score        sql.NullFloat64
	CVSSv3Severity     sql.NullString
	CVSSv3Vector       sql.NullString
	CVSSv31Score       sql.NullFloat64
	CVSSv31Severity    sql.NullString
	CVSSv31Vector      sql.NullString
	CVSSv40Score       sql.NullFloat64
	CVSSv40Severity    sql.NullString
	CVSSv40Vector      sql.NullString
	PublishedAt        sql.NullTime
	LastModifiedAt     sql.NullTime
	References         []string
	IngestedAt         time.Time
	KEVAddedAt         sql.NullTime
	KEVKnownRansomware sql.NullBool
	EPSSScore          sql.NullFloat64
	EPSSPercentile     sql.NullFloat64
}

// CPELeaf is one applicability statement for a CVE.
type CPELeaf struct {
	ID                    uint64
	CVEID                 string
	Vendor                string
	Product               string
	VersionStartIncluding sql.NullString
	VersionStartExcluding sql.NullString
	VersionEndIncluding   sql.NullString
	VersionEndExcluding   sql.NullString
	ExactVersion          sql.NullString
	RawCPE                string
	Vulnerable            bool
	TargetSW              sql.NullString
	TargetHW              sql.NullString
	Negate                bool
}

// Repository describes persistence of the mirrored NVD catalog.
type Repository interface {
	UpsertCVE(ctx context.Context, cve *CVE, rawJSON []byte) error
	ReplaceCPELeaves(ctx context.Context, cveID string, leaves []CPELeaf) error
	GetByID(ctx context.Context, id string) (*CVE, error)
	GetByIDs(ctx context.Context, ids []string) (map[string]*CVE, error)
	LeavesByVendorProducts(ctx context.Context, pairs []VendorProduct) ([]CPELeaf, error)
	ApplyKEV(ctx context.Context, rows []KEVRow) (int, error)
	ApplyEPSS(ctx context.Context, rows []EPSSRow) (int, error)
	Count(ctx context.Context) (int, error)
	MaxLastModifiedAt(ctx context.Context) (sql.NullTime, error)
	WithTx(tx pgx.Tx) Repository
}

// KEVRow is a CISA KEV record ready to upsert into uv_cve.
type KEVRow struct {
	CVEID           string
	AddedAt         sql.NullTime
	DueDate         sql.NullTime
	KnownRansomware sql.NullBool
}

// EPSSRow is one EPSS scoring entry ready to upsert into uv_cve.
type EPSSRow struct {
	CVEID      string
	Score      float64
	Percentile float64
	ScoredAt   time.Time
}

// VendorProduct is a (vendor, product) lookup tuple.
type VendorProduct struct {
	Vendor  string
	Product string
}

// PostgreSQL implements CatalogRepository.
type PostgreSQL struct {
	db pgkit.Querier
}

// NewPostgreSQL builds a CatalogRepository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{db: pool}
}

// WithTx routes every query through tx.
func (p *PostgreSQL) WithTx(tx pgx.Tx) Repository {
	return &PostgreSQL{db: tx}
}

// UpsertCVE inserts or refreshes one CVE record. rawJSON may be nil, in which
// case raw_json stays NULL (the worker's CVE_SYNC_STORE_RAW_JSON switch uses
// this to skip the ~5x storage overhead of mirroring the upstream payload).
func (p *PostgreSQL) UpsertCVE(ctx context.Context, cve *CVE, rawJSON []byte) error {
	refsJSON, err := json.Marshal(cve.References)
	if err != nil {
		return fmt.Errorf("can't marshal cve references: %w", err)
	}

	source := cve.Source
	if source == "" {
		source = "nvd"
	}

	var rawArg any = nil
	if len(rawJSON) > 0 {
		rawArg = rawJSON
	}

	query, args, err := sq.Insert("uv_cve").
		Columns(
			"id", "source", "summary", "cvss_v3_score", "cvss_v3_severity",
			"cvss_v3_vector", "cvss_v31_score", "cvss_v31_severity", "cvss_v31_vector",
			"cvss_v40_score", "cvss_v40_severity", "cvss_v40_vector",
			"published_at", "last_modified_at", "refs",
			"raw_json", "ingested_at",
		).
		Values(
			cve.ID, source, cve.Summary, cve.CVSSv3Score, cve.CVSSv3Severity,
			cve.CVSSv3Vector, cve.CVSSv31Score, cve.CVSSv31Severity, cve.CVSSv31Vector,
			cve.CVSSv40Score, cve.CVSSv40Severity, cve.CVSSv40Vector,
			cve.PublishedAt, cve.LastModifiedAt, refsJSON,
			rawArg, time.Now().UTC(),
		).
		Suffix(`ON CONFLICT (id) DO UPDATE SET
    source            = EXCLUDED.source,
    summary           = EXCLUDED.summary,
    cvss_v3_score     = EXCLUDED.cvss_v3_score,
    cvss_v3_severity  = EXCLUDED.cvss_v3_severity,
    cvss_v3_vector    = EXCLUDED.cvss_v3_vector,
    cvss_v31_score    = EXCLUDED.cvss_v31_score,
    cvss_v31_severity = EXCLUDED.cvss_v31_severity,
    cvss_v31_vector   = EXCLUDED.cvss_v31_vector,
    cvss_v40_score    = EXCLUDED.cvss_v40_score,
    cvss_v40_severity = EXCLUDED.cvss_v40_severity,
    cvss_v40_vector   = EXCLUDED.cvss_v40_vector,
    published_at      = EXCLUDED.published_at,
    last_modified_at  = EXCLUDED.last_modified_at,
    refs              = EXCLUDED.refs,
    raw_json          = EXCLUDED.raw_json,
    ingested_at       = EXCLUDED.ingested_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert cve query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert cve: %w", pgkit.Handle(err))
	}

	return nil
}

// ReplaceCPELeaves deletes all applicability rows for cveID and inserts the
// new set. Doing this in one shot keeps things consistent when the upstream
// catalog mutates the list of affected products.
func (p *PostgreSQL) ReplaceCPELeaves(ctx context.Context, cveID string, leaves []CPELeaf) error {
	deleteQuery, deleteArgs, err := sq.Delete("uv_cve_cpe").
		Where(squirrel.Eq{"cve_id": cveID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build delete cve cpe query: %w", err)
	}

	if _, execErr := p.db.Exec(ctx, deleteQuery, deleteArgs...); execErr != nil {
		return fmt.Errorf("can't clear cve cpe leaves: %w", pgkit.Handle(execErr))
	}

	if len(leaves) == 0 {
		return nil
	}

	cols := []string{
		"cve_id", "vendor", "product", "version_start_including",
		"version_start_excluding", "version_end_including", "version_end_excluding",
		"exact_version", "raw_cpe", "vulnerable",
		"target_sw", "target_hw", "negate",
	}

	for start := 0; start < len(leaves); start += cpeLeafInsertBatchRows {
		end := start + cpeLeafInsertBatchRows
		if end > len(leaves) {
			end = len(leaves)
		}

		insert := sq.Insert("uv_cve_cpe").Columns(cols...)

		for _, leaf := range leaves[start:end] {
			insert = insert.Values(
				cveID, leaf.Vendor, leaf.Product,
				leaf.VersionStartIncluding, leaf.VersionStartExcluding,
				leaf.VersionEndIncluding, leaf.VersionEndExcluding,
				leaf.ExactVersion, leaf.RawCPE, leaf.Vulnerable,
				leaf.TargetSW, leaf.TargetHW, leaf.Negate,
			)
		}

		query, args, err := insert.ToSql()
		if err != nil {
			return fmt.Errorf("can't build insert cve cpe query: %w", err)
		}

		if _, err := p.db.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("can't insert cve cpe leaves: %w", pgkit.Handle(err))
		}
	}

	return nil
}

var cveColumns = []string{
	"id", "source", "summary", "cvss_v3_score", "cvss_v3_severity",
	"cvss_v3_vector", "cvss_v31_score", "cvss_v31_severity", "cvss_v31_vector",
	"cvss_v40_score", "cvss_v40_severity", "cvss_v40_vector",
	"published_at", "last_modified_at", "refs", "ingested_at",
	"kev_added_at", "kev_known_ransomware", "epss_score", "epss_percentile",
}

// GetByID fetches one CVE record without its raw payload.
func (p *PostgreSQL) GetByID(ctx context.Context, id string) (*CVE, error) {
	query, args, err := sq.Select(cveColumns...).
		From("uv_cve").
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get cve query: %w", err)
	}

	var (
		cve     CVE
		refsRaw []byte
	)

	err = p.db.QueryRow(ctx, query, args...).Scan(
		&cve.ID, &cve.Source, &cve.Summary, &cve.CVSSv3Score, &cve.CVSSv3Severity,
		&cve.CVSSv3Vector, &cve.CVSSv31Score, &cve.CVSSv31Severity, &cve.CVSSv31Vector,
		&cve.CVSSv40Score, &cve.CVSSv40Severity, &cve.CVSSv40Vector,
		&cve.PublishedAt, &cve.LastModifiedAt, &refsRaw,
		&cve.IngestedAt,
		&cve.KEVAddedAt, &cve.KEVKnownRansomware, &cve.EPSSScore, &cve.EPSSPercentile,
	)
	if err != nil {
		return nil, pgkit.Handle(err)
	}

	if len(refsRaw) > 0 {
		if err := json.Unmarshal(refsRaw, &cve.References); err != nil {
			return nil, fmt.Errorf("can't unmarshal cve references: %w", err)
		}
	}

	return &cve, nil
}

// GetByIDs returns every CVE whose id is in ids, keyed by id. Missing ids are
// silently absent from the result (callers should not assume presence).
func (p *PostgreSQL) GetByIDs(ctx context.Context, ids []string) (map[string]*CVE, error) {
	if len(ids) == 0 {
		return map[string]*CVE{}, nil
	}

	query, args, err := sq.Select(cveColumns...).
		From("uv_cve").
		Where(squirrel.Eq{"id": ids}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build batch get cve query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query cves by ids: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make(map[string]*CVE, len(ids))

	for rows.Next() {
		var (
			cve     CVE
			refsRaw []byte
		)

		err := rows.Scan(
			&cve.ID, &cve.Source, &cve.Summary, &cve.CVSSv3Score, &cve.CVSSv3Severity,
			&cve.CVSSv3Vector, &cve.CVSSv31Score, &cve.CVSSv31Severity, &cve.CVSSv31Vector,
			&cve.CVSSv40Score, &cve.CVSSv40Severity, &cve.CVSSv40Vector,
			&cve.PublishedAt, &cve.LastModifiedAt, &refsRaw,
			&cve.IngestedAt,
			&cve.KEVAddedAt, &cve.KEVKnownRansomware, &cve.EPSSScore, &cve.EPSSPercentile,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan cve row: %w", pgkit.Handle(err))
		}

		if len(refsRaw) > 0 {
			if err := json.Unmarshal(refsRaw, &cve.References); err != nil {
				return nil, fmt.Errorf("can't unmarshal cve references: %w", err)
			}
		}

		out[cve.ID] = &cve
	}

	return out, rows.Err()
}

// applyBulkBatch caps how many rows are folded into one UPDATE…FROM (VALUES …)
// statement. 1000 keeps the planner happy and stays well under pgx's
// 65535-bind-param ceiling for the 4-column KEV / 4-column EPSS shape.
const applyBulkBatch = 1000

// ApplyKEV updates kev_* columns for CVEs that are already in the catalog.
// Rows referencing unknown CVE ids are skipped silently; the caller can rely
// on the returned count to detect feeds drifting ahead of the local mirror.
//
// The bulk UPDATE…FROM (VALUES …) shape replaces the original per-row N+1
// loop (10k+ KEV entries × ~1-5 ms round-trip = tens of seconds on bootstrap).
func (p *PostgreSQL) ApplyKEV(ctx context.Context, rows []KEVRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	updated := 0

	for start := 0; start < len(rows); start += applyBulkBatch {
		end := start + applyBulkBatch
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[start:end]

		var (
			ids        = make([]string, 0, len(batch))
			addedAt    = make([]sql.NullTime, 0, len(batch))
			dueDate    = make([]sql.NullTime, 0, len(batch))
			ransomware = make([]sql.NullBool, 0, len(batch))
		)

		for _, r := range batch {
			ids = append(ids, r.CVEID)
			addedAt = append(addedAt, r.AddedAt)
			dueDate = append(dueDate, r.DueDate)
			ransomware = append(ransomware, r.KnownRansomware)
		}

		// Bulk join: lift one batch into a transient relation via UNNEST and
		// fold it into a single UPDATE … FROM (...) AS data WHERE c.id =
		// data.id. The squirrel builder owns parameter binding; the suffix
		// expression carries the join shape Postgres expects.
		query, args, err := sq.Update("uv_cve").
			PrefixExpr(squirrel.Expr("")).
			Set("kev_added_at", squirrel.Expr("data.added_at")).
			Set("kev_due_date", squirrel.Expr("data.due_date")).
			Set("kev_known_ransomware", squirrel.Expr("data.ransomware")).
			Suffix(`FROM (
    SELECT * FROM UNNEST(
        ?::text[],
        ?::timestamp[],
        ?::date[],
        ?::boolean[]
    ) AS t(id, added_at, due_date, ransomware)
) AS data
WHERE uv_cve.id = data.id`, ids, addedAt, dueDate, ransomware).
			ToSql()
		if err != nil {
			return updated, fmt.Errorf("can't build bulk-apply KEV query: %w", err)
		}

		tag, err := p.db.Exec(ctx, query, args...)
		if err != nil {
			return updated, fmt.Errorf("can't bulk-apply KEV rows: %w", pgkit.Handle(err))
		}

		updated += int(tag.RowsAffected())
	}

	return updated, nil
}

// ApplyEPSS updates epss_* columns for CVEs that are already in the catalog.
// Bulk-batched for the same reason as ApplyKEV — EPSS feed is ~300k rows on
// bootstrap and the row-at-a-time loop dominated catch-up latency.
func (p *PostgreSQL) ApplyEPSS(ctx context.Context, rows []EPSSRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	updated := 0

	for start := 0; start < len(rows); start += applyBulkBatch {
		end := start + applyBulkBatch
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[start:end]

		var (
			ids        = make([]string, 0, len(batch))
			score      = make([]float64, 0, len(batch))
			percentile = make([]float64, 0, len(batch))
			scoredAt   = make([]time.Time, 0, len(batch))
		)

		for _, r := range batch {
			ids = append(ids, r.CVEID)
			score = append(score, r.Score)
			percentile = append(percentile, r.Percentile)
			scoredAt = append(scoredAt, r.ScoredAt)
		}

		query, args, err := sq.Update("uv_cve").
			Set("epss_score", squirrel.Expr("data.score")).
			Set("epss_percentile", squirrel.Expr("data.percentile")).
			Set("epss_scored_at", squirrel.Expr("data.scored_at")).
			Suffix(`FROM (
    SELECT * FROM UNNEST(
        ?::text[],
        ?::double precision[],
        ?::double precision[],
        ?::timestamp[]
    ) AS t(id, score, percentile, scored_at)
) AS data
WHERE uv_cve.id = data.id`, ids, score, percentile, scoredAt).
			ToSql()
		if err != nil {
			return updated, fmt.Errorf("can't build bulk-apply EPSS query: %w", err)
		}

		tag, err := p.db.Exec(ctx, query, args...)
		if err != nil {
			return updated, fmt.Errorf("can't bulk-apply EPSS rows: %w", pgkit.Handle(err))
		}

		updated += int(tag.RowsAffected())
	}

	return updated, nil
}

// Count returns the number of CVEs mirrored locally.
func (p *PostgreSQL) Count(ctx context.Context) (int, error) {
	query, args, err := sq.Select("COUNT(*)").From("uv_cve").ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count cve query: %w", err)
	}

	var n int

	if err := p.db.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count uv_cve: %w", pgkit.Handle(err))
	}

	return n, nil
}

// MaxLastModifiedAt returns the most recent last_modified_at across all CVEs
// or a NULL sql.NullTime when the catalog is empty.
func (p *PostgreSQL) MaxLastModifiedAt(ctx context.Context) (sql.NullTime, error) {
	query, args, err := sq.Select("MAX(last_modified_at)").From("uv_cve").ToSql()
	if err != nil {
		return sql.NullTime{}, fmt.Errorf("can't build max mtime query: %w", err)
	}

	var mtime sql.NullTime

	if err := p.db.QueryRow(ctx, query, args...).Scan(&mtime); err != nil {
		return sql.NullTime{}, fmt.Errorf("can't query catalog mtime: %w", pgkit.Handle(err))
	}

	return mtime, nil
}

// LeavesByVendorProducts returns all applicability leaves for the supplied
// vendor/product tuples. An empty input yields no rows.
func (p *PostgreSQL) LeavesByVendorProducts(ctx context.Context, pairs []VendorProduct) ([]CPELeaf, error) {
	if len(pairs) == 0 {
		return nil, nil
	}

	or := squirrel.Or{}

	for _, pair := range pairs {
		or = append(or, squirrel.Eq{"vendor": pair.Vendor, "product": pair.Product})
	}

	query, args, err := sq.Select(
		"id", "cve_id", "vendor", "product",
		"version_start_including", "version_start_excluding",
		"version_end_including", "version_end_excluding",
		"exact_version", "raw_cpe", "vulnerable",
		"target_sw", "target_hw", "negate",
	).
		From("uv_cve_cpe").
		Where(or).
		Where(squirrel.Eq{"vulnerable": true}).
		Where(squirrel.Eq{"negate": false}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build leaves query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query cve cpe leaves: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]CPELeaf, 0, 64)

	for rows.Next() {
		var leaf CPELeaf

		err := rows.Scan(
			&leaf.ID, &leaf.CVEID, &leaf.Vendor, &leaf.Product,
			&leaf.VersionStartIncluding, &leaf.VersionStartExcluding,
			&leaf.VersionEndIncluding, &leaf.VersionEndExcluding,
			&leaf.ExactVersion, &leaf.RawCPE, &leaf.Vulnerable,
			&leaf.TargetSW, &leaf.TargetHW, &leaf.Negate,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan cve cpe leaf: %w", pgkit.Handle(err))
		}

		out = append(out, leaf)
	}

	return out, rows.Err()
}
