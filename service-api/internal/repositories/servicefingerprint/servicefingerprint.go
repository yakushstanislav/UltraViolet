// Package servicefingerprint stores product-level metadata captured for a
// service. Since migration 16 a single service can carry several rows —
// one per stack layer (web_server / runtime / cms / js_library / …) — so
// CVE matching covers the whole technology stack, not just one product.
package servicefingerprint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/utf8safe"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Fingerprint is one detected technology layer for a service. Multiple
// rows can share the same service_id; the unique key is
// (service_id, product, COALESCE(version,”), source).
type Fingerprint struct {
	ID              int64
	ServiceID       uint64
	Product         string
	Version         sql.NullString
	Edition         sql.NullString
	Source          string
	Role            sql.NullString
	ClusterRole     sql.NullString
	ClusterName     sql.NullString
	AuthRequired    sql.NullBool
	TLSRequired     sql.NullBool
	Anonymous       bool
	RawJSON         []byte
	FingerprintHash string
	CapturedAt      time.Time
}

// Repository is the storage contract for service fingerprints.
type Repository interface {
	Upsert(ctx context.Context, fp *Fingerprint) error
	ReplaceAllForService(ctx context.Context, serviceID uint64, components []*Fingerprint) error
	SetFingerprintHash(ctx context.Context, serviceID uint64, fingerprintHash string) error
	GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64][]*Fingerprint, error)
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

// WithTx returns a Repository that routes every query through tx.
func (p *PostgreSQL) WithTx(tx pgx.Tx) Repository {
	return &PostgreSQL{db: tx}
}

var fpColumns = []string{
	"id", "service_id", "product", "version", "edition", "source", "role",
	"cluster_role", "cluster_name", "auth_required", "tls_required",
	"anonymous", "raw_json", "fingerprint_hash", "captured_at",
}

var fpInsertColumns = []string{
	"service_id", "product", "version", "edition", "source", "role",
	"cluster_role", "cluster_name", "auth_required", "tls_required",
	"anonymous", "raw_json", "fingerprint_hash", "captured_at",
}

const defaultSource = "legacy"

// Upsert inserts or refreshes a single technology component for the given
// service. The conflict target matches the (service_id, product,
// COALESCE(version,”), source) unique index introduced in migration 16.
func (p *PostgreSQL) Upsert(ctx context.Context, fp *Fingerprint) error {
	return upsertExec(ctx, p.db, fp)
}

func upsertExec(ctx context.Context, q pgkit.Querier, fp *Fingerprint) error {
	capturedAt := fp.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}

	rawJSON := utf8safe.SanitizeJSONB(fp.RawJSON)
	if len(rawJSON) == 0 {
		rawJSON = []byte("null")
	}

	source := fp.Source
	if source == "" {
		source = defaultSource
	}

	fpHash := fp.FingerprintHash
	if fpHash == "" {
		fpHash = FingerprintHash(fp)
	}

	query, args, err := sq.Insert("uv_service_fingerprint").
		Columns(fpInsertColumns...).
		Values(
			fp.ServiceID, fp.Product, fp.Version, fp.Edition, source, fp.Role,
			fp.ClusterRole, fp.ClusterName, fp.AuthRequired, fp.TLSRequired,
			fp.Anonymous, rawJSON, fpHash, capturedAt,
		).
		Suffix(`ON CONFLICT (service_id, product, COALESCE(version, ''), source) DO UPDATE SET
    edition          = EXCLUDED.edition,
    role             = EXCLUDED.role,
    cluster_role     = EXCLUDED.cluster_role,
    cluster_name     = EXCLUDED.cluster_name,
    auth_required    = EXCLUDED.auth_required,
    tls_required     = EXCLUDED.tls_required,
    anonymous        = EXCLUDED.anonymous,
    raw_json         = EXCLUDED.raw_json,
    fingerprint_hash = EXCLUDED.fingerprint_hash,
    captured_at      = EXCLUDED.captured_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert service fingerprint query: %w", err)
	}

	if _, err := q.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert service fingerprint: %w", pgkit.Handle(err))
	}

	return nil
}

// ReplaceAllForService atomically replaces the component set for one
// service: upserts each component, then deletes any rows for the service
// whose (product, version, source) triple is no longer present. When
// components is empty all rows for the service are removed.
//
// The whole replace runs inside a single transaction so a mid-loop failure
// can't leave half-upserted plus pre-existing stale rows around; CVE
// matching otherwise produces wrong findings until the next probe re-runs.
// If the repo is already bound to a tx (via WithTx) we reuse it so an outer
// transactional caller stays in control of commit/rollback.
func (p *PostgreSQL) ReplaceAllForService(ctx context.Context, serviceID uint64, components []*Fingerprint) error {
	if tx, ok := p.db.(pgx.Tx); ok {
		return replaceAllForServiceTx(ctx, tx, serviceID, components)
	}

	pool, ok := p.db.(*pgxpool.Pool)
	if !ok {
		return replaceAllForServiceTx(ctx, p.db, serviceID, components)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can't begin replace fingerprints tx: %w", pgkit.Handle(err))
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if err := replaceAllForServiceTx(ctx, tx, serviceID, components); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("can't commit replace fingerprints tx: %w", pgkit.Handle(err))
	}

	return nil
}

func replaceAllForServiceTx(ctx context.Context, q pgkit.Querier, serviceID uint64, components []*Fingerprint) error {
	for _, comp := range components {
		comp.ServiceID = serviceID

		if err := upsertExec(ctx, q, comp); err != nil {
			return err
		}
	}

	if len(components) == 0 {
		query, args, err := sq.Delete("uv_service_fingerprint").
			Where(squirrel.Eq{"service_id": serviceID}).
			ToSql()
		if err != nil {
			return fmt.Errorf("can't build delete fingerprints query: %w", err)
		}

		if _, err := q.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("can't delete service fingerprints: %w", pgkit.Handle(err))
		}

		return nil
	}

	products := make([]string, 0, len(components))
	versions := make([]string, 0, len(components))
	sources := make([]string, 0, len(components))

	for _, comp := range components {
		products = append(products, comp.Product)
		versions = append(versions, comp.Version.String)

		source := comp.Source
		if source == "" {
			source = defaultSource
		}

		sources = append(sources, source)
	}

	query, args, err := sq.Delete("uv_service_fingerprint").
		Where(squirrel.Eq{"service_id": serviceID}).
		Where(
			squirrel.Expr(
				`(product, COALESCE(version, ''), source) NOT IN (
                    SELECT * FROM UNNEST(?::text[], ?::text[], ?::text[])
                )`,
				products, versions, sources,
			),
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build prune fingerprints query: %w", err)
	}

	if _, err := q.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't prune stale service fingerprints: %w", pgkit.Handle(err))
	}

	return nil
}

// SetFingerprintHash backfills the stable hash column on every component
// row for the service. Used by cvematch when the worker computes the
// set-level hash and needs to flip the bookkeeping rows so subsequent
// scans skip unchanged stacks.
func (p *PostgreSQL) SetFingerprintHash(ctx context.Context, serviceID uint64, fingerprintHash string) error {
	if fingerprintHash == "" {
		return nil
	}

	query, args, err := sq.Update("uv_service_fingerprint").
		Set("fingerprint_hash", fingerprintHash).
		Where(squirrel.Eq{"service_id": serviceID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update fingerprint hash query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update fingerprint hash: %w", pgkit.Handle(err))
	}

	return nil
}

// GetByServiceIDs returns a map of service_id → ordered slice of component
// fingerprints for that service. The slice is sorted by (role, product,
// source) so callers get stable ordering across calls.
func (p *PostgreSQL) GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64][]*Fingerprint, error) {
	out := make(map[uint64][]*Fingerprint, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(fpColumns...).
		From("uv_service_fingerprint").
		Where("service_id = ANY(?)", serviceIDs).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get service fingerprints query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query service fingerprints: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var fp Fingerprint

		var fingerprintHash sql.NullString

		err := rows.Scan(
			&fp.ID,
			&fp.ServiceID,
			&fp.Product,
			&fp.Version,
			&fp.Edition,
			&fp.Source,
			&fp.Role,
			&fp.ClusterRole,
			&fp.ClusterName,
			&fp.AuthRequired,
			&fp.TLSRequired,
			&fp.Anonymous,
			&fp.RawJSON,
			&fingerprintHash,
			&fp.CapturedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan service fingerprint: %w", pgkit.Handle(err))
		}

		if fingerprintHash.Valid {
			fp.FingerprintHash = fingerprintHash.String
		}

		out[fp.ServiceID] = append(out[fp.ServiceID], &fp)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate service fingerprints: %w", err)
	}

	for serviceID := range out {
		sortComponents(out[serviceID])
	}

	return out, nil
}

func sortComponents(comps []*Fingerprint) {
	sort.SliceStable(comps, func(i, j int) bool {
		if comps[i].Role.String != comps[j].Role.String {
			return comps[i].Role.String < comps[j].Role.String
		}

		if comps[i].Product != comps[j].Product {
			return comps[i].Product < comps[j].Product
		}

		return comps[i].Source < comps[j].Source
	})
}

// FingerprintHash returns a stable SHA-256 hex digest of the fields that
// drive CVE matching for one component. Identical probes produce the same
// hash even when captured_at is refreshed.
func FingerprintHash(fp *Fingerprint) string {
	if fp == nil {
		return ""
	}

	h := sha256.New()
	writeHashField(h, fp.Product)
	writeHashNullString(h, fp.Version)
	writeHashNullString(h, fp.Edition)
	writeHashNullString(h, fp.ClusterRole)
	writeHashField(h, fp.Source)
	_, _ = h.Write(fp.RawJSON)

	return hex.EncodeToString(h.Sum(nil))
}

// SetHashOfComponents returns a stable hash over the *set* of components on
// a service (sorted by product/version/source). Used as the cvematch
// re-evaluation trigger: when the set hash differs from the value stored
// in uv_service_match_state, the worker re-runs matching.
func SetHashOfComponents(components []*Fingerprint) string {
	if len(components) == 0 {
		return ""
	}

	type sortable struct {
		product string
		version string
		source  string
	}

	rows := make([]sortable, 0, len(components))

	for _, comp := range components {
		rows = append(rows, sortable{
			product: comp.Product,
			version: comp.Version.String,
			source:  comp.Source,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].product != rows[j].product {
			return rows[i].product < rows[j].product
		}

		if rows[i].version != rows[j].version {
			return rows[i].version < rows[j].version
		}

		return rows[i].source < rows[j].source
	})

	h := sha256.New()

	for _, row := range rows {
		writeHashField(h, row.product)
		writeHashField(h, row.version)
		writeHashField(h, row.source)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func writeHashField(h interface{ Write([]byte) (int, error) }, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}

func writeHashNullString(h interface{ Write([]byte) (int, error) }, ns sql.NullString) {
	if ns.Valid {
		writeHashField(h, ns.String)

		return
	}

	_, _ = h.Write([]byte{0})
}
