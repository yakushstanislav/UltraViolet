// Package tlscertificate stores TLS leaf certificates observed during probing.
package tlscertificate

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

// TLSCertificate is the persisted leaf cert observed for one service.
type TLSCertificate struct {
	ServiceID         uint64
	Subject           sql.NullString
	Issuer            sql.NullString
	FingerprintSHA256 sql.NullString
	NotBefore         sql.NullTime
	NotAfter          sql.NullTime
	RawPEM            sql.NullString
	SANs              []string
	JARMFingerprint   sql.NullString
	TLSVersion        sql.NullString
	CipherSuite       sql.NullString
	JA3SHash          sql.NullString
	JA4SHash          sql.NullString
	SecurityGrade     sql.NullString
}

// TLSFinding is one detected security issue against a service's TLS
// handshake (expired cert, weak protocol, hostname mismatch, …).
type TLSFinding struct {
	ServiceID  uint64
	Severity   string
	Code       string
	Detail     sql.NullString
	CapturedAt time.Time
}

// TLSChainNode is one stored intermediate/root cert for a service.
type TLSChainNode struct {
	ServiceID         uint64
	ChainPosition     int
	Subject           sql.NullString
	Issuer            sql.NullString
	FingerprintSHA256 sql.NullString
	NotBefore         sql.NullTime
	NotAfter          sql.NullTime
	RawPEM            sql.NullString
	SANs              []string
	CapturedAt        time.Time
}

// IssuerBucket is one row of GROUP BY issuer.
type IssuerBucket struct {
	Issuer string
	Count  uint64
}

// Repository is the storage contract for TLS certificates.
type Repository interface {
	Upsert(ctx context.Context, cert *TLSCertificate) error
	UpsertChain(ctx context.Context, serviceID uint64, nodes []TLSChainNode) error
	UpsertFindings(ctx context.Context, serviceID uint64, findings []TLSFinding) error
	GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*TLSCertificate, error)
	GetChainByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64][]TLSChainNode, error)
	GetFindingsByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64][]TLSFinding, error)
	TopIssuers(ctx context.Context, limit uint64) ([]IssuerBucket, error)
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

var certColumns = []string{
	"service_id", "subject", "issuer", "fingerprint_sha256", "not_before", "not_after", "raw_pem",
	"sans", "jarm_fingerprint", "tls_version", "cipher_suite", "ja3s_hash", "ja4s_hash",
	"security_grade",
}

// Upsert inserts or refreshes the TLS certificate snapshot for the service.
func (p *PostgreSQL) Upsert(ctx context.Context, cert *TLSCertificate) error {
	query, args, err := sq.Insert("uv_tls_certificate").
		Columns(certColumns...).
		Values(
			cert.ServiceID, cert.Subject, cert.Issuer,
			cert.FingerprintSHA256, cert.NotBefore, cert.NotAfter, cert.RawPEM,
			cert.SANs, cert.JARMFingerprint, cert.TLSVersion, cert.CipherSuite,
			cert.JA3SHash, cert.JA4SHash,
			cert.SecurityGrade,
		).
		Suffix(`ON CONFLICT (service_id) DO UPDATE SET
    subject            = EXCLUDED.subject,
    issuer             = EXCLUDED.issuer,
    fingerprint_sha256 = EXCLUDED.fingerprint_sha256,
    not_before         = EXCLUDED.not_before,
    not_after          = EXCLUDED.not_after,
    raw_pem            = EXCLUDED.raw_pem,
    sans               = EXCLUDED.sans,
    jarm_fingerprint   = EXCLUDED.jarm_fingerprint,
    tls_version        = EXCLUDED.tls_version,
    cipher_suite       = EXCLUDED.cipher_suite,
    ja3s_hash          = EXCLUDED.ja3s_hash,
    ja4s_hash          = EXCLUDED.ja4s_hash,
    security_grade     = EXCLUDED.security_grade`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert TLS certificate query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert TLS certificate: %w", pgkit.Handle(err))
	}

	return nil
}

// UpsertChain replaces the stored chain for the given service with the new
// nodes (positions are 1-based for the first intermediate).
func (p *PostgreSQL) UpsertChain(ctx context.Context, serviceID uint64, nodes []TLSChainNode) error {
	// DELETE + INSERT must be atomic: a failed INSERT after a committed DELETE
	// would leave the service with no chain rows until the next scan re-probed
	// it. If we are already inside a transaction (WithTx), reuse it; otherwise
	// open one here.
	if tx, ok := p.db.(pgx.Tx); ok {
		return upsertChainTx(ctx, tx, serviceID, nodes)
	}

	pool, ok := p.db.(*pgxpool.Pool)
	if !ok {
		// Querier we don't recognise — fall back to non-atomic for safety; this
		// branch should be unreachable with the current wiring.
		return upsertChainExec(ctx, p.db, serviceID, nodes)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can't begin upsert TLS chain tx: %w", pgkit.Handle(err))
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if err := upsertChainTx(ctx, tx, serviceID, nodes); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("can't commit upsert TLS chain tx: %w", pgkit.Handle(err))
	}

	return nil
}

func upsertChainTx(ctx context.Context, q pgkit.Querier, serviceID uint64, nodes []TLSChainNode) error {
	return upsertChainExec(ctx, q, serviceID, nodes)
}

func upsertChainExec(ctx context.Context, q pgkit.Querier, serviceID uint64, nodes []TLSChainNode) error {
	deleteQuery, deleteArgs, err := sq.Delete("uv_tls_chain_certificate").
		Where(squirrel.Eq{"service_id": serviceID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build clear TLS chain query: %w", err)
	}

	if _, err = q.Exec(ctx, deleteQuery, deleteArgs...); err != nil {
		return fmt.Errorf("can't clear TLS chain: %w", pgkit.Handle(err))
	}

	if len(nodes) == 0 {
		return nil
	}

	insert := sq.Insert("uv_tls_chain_certificate").Columns(
		"service_id", "chain_position", "subject", "issuer", "fingerprint_sha256",
		"not_before", "not_after", "raw_pem", "sans", "captured_at",
	)

	for _, node := range nodes {
		insert = insert.Values(
			serviceID, node.ChainPosition, node.Subject, node.Issuer, node.FingerprintSHA256,
			node.NotBefore, node.NotAfter, node.RawPEM, node.SANs, node.CapturedAt,
		)
	}

	query, args, err := insert.ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert TLS chain query: %w", err)
	}

	if _, err := q.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert TLS chain: %w", pgkit.Handle(err))
	}

	return nil
}

// GetChainByServiceIDs returns service_id → ordered chain nodes.
func (p *PostgreSQL) GetChainByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64][]TLSChainNode, error) {
	out := make(map[uint64][]TLSChainNode, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(
		"service_id", "chain_position", "subject", "issuer", "fingerprint_sha256",
		"not_before", "not_after", "raw_pem", "sans", "captured_at",
	).
		From("uv_tls_chain_certificate").
		Where("service_id = ANY(?)", serviceIDs).
		OrderBy("service_id ASC", "chain_position ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get TLS chain query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query TLS chain: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var node TLSChainNode

		err := rows.Scan(
			&node.ServiceID, &node.ChainPosition, &node.Subject, &node.Issuer,
			&node.FingerprintSHA256, &node.NotBefore, &node.NotAfter,
			&node.RawPEM, &node.SANs, &node.CapturedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan TLS chain node: %w", pgkit.Handle(err))
		}

		out[node.ServiceID] = append(out[node.ServiceID], node)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate TLS chain rows: %w", err)
	}

	return out, nil
}

// GetByServiceIDs returns a map of service_id → TLSCertificate.
func (p *PostgreSQL) GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*TLSCertificate, error) {
	out := make(map[uint64]*TLSCertificate, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(certColumns...).
		From("uv_tls_certificate").
		Where("service_id = ANY(?)", serviceIDs).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get TLS certificates query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query TLS certificates: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var cert TLSCertificate

		err := rows.Scan(
			&cert.ServiceID,
			&cert.Subject,
			&cert.Issuer,
			&cert.FingerprintSHA256,
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.RawPEM,
			&cert.SANs,
			&cert.JARMFingerprint,
			&cert.TLSVersion,
			&cert.CipherSuite,
			&cert.JA3SHash,
			&cert.JA4SHash,
			&cert.SecurityGrade,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan TLS certificate: %w", pgkit.Handle(err))
		}

		out[cert.ServiceID] = &cert
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate TLS certificates: %w", err)
	}

	return out, nil
}

// TopIssuers returns the most common TLS issuers, ordered by certificate count.
func (p *PostgreSQL) TopIssuers(ctx context.Context, limit uint64) ([]IssuerBucket, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select("issuer", "COUNT(*)::bigint").
		From("uv_tls_certificate").
		Where("issuer IS NOT NULL").
		Where("length(trim(both from issuer)) > 0").
		GroupBy("issuer").
		OrderBy("COUNT(*) DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top TLS issuers query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top TLS issuers: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]IssuerBucket, 0, limit)

	for rows.Next() {
		var (
			issuer string
			n      int64
		)

		if err := rows.Scan(&issuer, &n); err != nil {
			return nil, fmt.Errorf("can't scan TLS issuer bucket: %w", pgkit.Handle(err))
		}

		if n < 0 {
			n = 0
		}

		out = append(out, IssuerBucket{
			Issuer: issuer,
			Count:  uint64(n),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate TLS issuer buckets: %w", err)
	}

	return out, nil
}

// UpsertFindings replaces the stored findings for the given service with
// the provided slice. Replace-all keeps the table tidy: every probe pass
// owns the full finding set for its service, and a service that becomes
// clean simply ends up with no rows.
func (p *PostgreSQL) UpsertFindings(ctx context.Context, serviceID uint64, findings []TLSFinding) error {
	deleteQuery, deleteArgs, err := sq.Delete("uv_tls_finding").
		Where(squirrel.Eq{"service_id": serviceID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build clear TLS findings query: %w", err)
	}

	if _, err = p.db.Exec(ctx, deleteQuery, deleteArgs...); err != nil {
		return fmt.Errorf("can't clear TLS findings: %w", pgkit.Handle(err))
	}

	if len(findings) == 0 {
		return nil
	}

	insert := sq.Insert("uv_tls_finding").Columns(
		"service_id", "severity", "code", "detail", "captured_at",
	)

	for _, f := range findings {
		capturedAt := f.CapturedAt
		if capturedAt.IsZero() {
			capturedAt = time.Now().UTC()
		}

		insert = insert.Values(serviceID, f.Severity, f.Code, f.Detail, capturedAt)
	}

	query, args, err := insert.ToSql()
	if err != nil {
		return fmt.Errorf("can't build insert TLS findings query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't insert TLS findings: %w", pgkit.Handle(err))
	}

	return nil
}

// GetFindingsByServiceIDs returns service_id → ordered findings.
func (p *PostgreSQL) GetFindingsByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64][]TLSFinding, error) {
	out := make(map[uint64][]TLSFinding, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(
		"service_id", "severity", "code", "detail", "captured_at",
	).
		From("uv_tls_finding").
		Where("service_id = ANY(?)", serviceIDs).
		OrderBy("service_id ASC", "id ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get TLS findings query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query TLS findings: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var finding TLSFinding

		err := rows.Scan(
			&finding.ServiceID,
			&finding.Severity,
			&finding.Code,
			&finding.Detail,
			&finding.CapturedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan TLS finding: %w", pgkit.Handle(err))
		}

		out[finding.ServiceID] = append(out[finding.ServiceID], finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate TLS findings: %w", err)
	}

	return out, nil
}
