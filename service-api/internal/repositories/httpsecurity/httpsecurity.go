// Package httpsecurity stores parsed HTTP security response headers,
// one row per service mirroring uv_http_response.
package httpsecurity

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

// HTTPSecurity is the persisted parsed-headers snapshot.
type HTTPSecurity struct {
	ServiceID                uint64
	HSTSMaxAge               sql.NullInt64
	HSTSIncludeSubdomains    bool
	HSTSPreload              bool
	CSPPresent               bool
	CSPHasUnsafeInline       bool
	CSPHasUnsafeEval         bool
	XFrameOptions            sql.NullString
	XContentTypeOptions      sql.NullString
	ReferrerPolicy           sql.NullString
	PermissionsPolicyPresent bool
	CORSAllowOrigin          sql.NullString
	CookieSecureCount        int
	CookieHTTPOnlyCount      int
	CookieSameSiteStrict     int
	CookieSameSiteLax        int
	CookieSameSiteNone       int
	CapturedAt               time.Time
}

// Repository is the storage contract for HTTP security snapshots.
type Repository interface {
	Upsert(ctx context.Context, snapshot *HTTPSecurity) error
	GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*HTTPSecurity, error)
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

var securityColumns = []string{
	"service_id",
	"hsts_max_age",
	"hsts_include_subdomains",
	"hsts_preload",
	"csp_present",
	"csp_has_unsafe_inline",
	"csp_has_unsafe_eval",
	"x_frame_options",
	"x_content_type_options",
	"referrer_policy",
	"permissions_policy_present",
	"cors_allow_origin",
	"cookie_secure_count",
	"cookie_httponly_count",
	"cookie_samesite_strict_count",
	"cookie_samesite_lax_count",
	"cookie_samesite_none_count",
	"captured_at",
}

// Upsert inserts or refreshes the security snapshot for the given service.
func (p *PostgreSQL) Upsert(ctx context.Context, snapshot *HTTPSecurity) error {
	capturedAt := snapshot.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}

	query, args, err := sq.Insert("uv_http_security").
		Columns(securityColumns...).
		Values(
			snapshot.ServiceID,
			snapshot.HSTSMaxAge,
			snapshot.HSTSIncludeSubdomains,
			snapshot.HSTSPreload,
			snapshot.CSPPresent,
			snapshot.CSPHasUnsafeInline,
			snapshot.CSPHasUnsafeEval,
			snapshot.XFrameOptions,
			snapshot.XContentTypeOptions,
			snapshot.ReferrerPolicy,
			snapshot.PermissionsPolicyPresent,
			snapshot.CORSAllowOrigin,
			snapshot.CookieSecureCount,
			snapshot.CookieHTTPOnlyCount,
			snapshot.CookieSameSiteStrict,
			snapshot.CookieSameSiteLax,
			snapshot.CookieSameSiteNone,
			capturedAt,
		).
		Suffix(`ON CONFLICT (service_id) DO UPDATE SET
    hsts_max_age                 = EXCLUDED.hsts_max_age,
    hsts_include_subdomains      = EXCLUDED.hsts_include_subdomains,
    hsts_preload                 = EXCLUDED.hsts_preload,
    csp_present                  = EXCLUDED.csp_present,
    csp_has_unsafe_inline        = EXCLUDED.csp_has_unsafe_inline,
    csp_has_unsafe_eval          = EXCLUDED.csp_has_unsafe_eval,
    x_frame_options              = EXCLUDED.x_frame_options,
    x_content_type_options       = EXCLUDED.x_content_type_options,
    referrer_policy              = EXCLUDED.referrer_policy,
    permissions_policy_present   = EXCLUDED.permissions_policy_present,
    cors_allow_origin            = EXCLUDED.cors_allow_origin,
    cookie_secure_count          = EXCLUDED.cookie_secure_count,
    cookie_httponly_count        = EXCLUDED.cookie_httponly_count,
    cookie_samesite_strict_count = EXCLUDED.cookie_samesite_strict_count,
    cookie_samesite_lax_count    = EXCLUDED.cookie_samesite_lax_count,
    cookie_samesite_none_count   = EXCLUDED.cookie_samesite_none_count,
    captured_at                  = EXCLUDED.captured_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert HTTP security query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert HTTP security: %w", pgkit.Handle(err))
	}

	return nil
}

// GetByServiceIDs returns a map of service_id → HTTPSecurity for the given ids.
func (p *PostgreSQL) GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*HTTPSecurity, error) {
	out := make(map[uint64]*HTTPSecurity, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(securityColumns...).
		From("uv_http_security").
		Where("service_id = ANY(?)", serviceIDs).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get HTTP security query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query HTTP security: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var snapshot HTTPSecurity

		err := rows.Scan(
			&snapshot.ServiceID,
			&snapshot.HSTSMaxAge,
			&snapshot.HSTSIncludeSubdomains,
			&snapshot.HSTSPreload,
			&snapshot.CSPPresent,
			&snapshot.CSPHasUnsafeInline,
			&snapshot.CSPHasUnsafeEval,
			&snapshot.XFrameOptions,
			&snapshot.XContentTypeOptions,
			&snapshot.ReferrerPolicy,
			&snapshot.PermissionsPolicyPresent,
			&snapshot.CORSAllowOrigin,
			&snapshot.CookieSecureCount,
			&snapshot.CookieHTTPOnlyCount,
			&snapshot.CookieSameSiteStrict,
			&snapshot.CookieSameSiteLax,
			&snapshot.CookieSameSiteNone,
			&snapshot.CapturedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan HTTP security: %w", pgkit.Handle(err))
		}

		out[snapshot.ServiceID] = &snapshot
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate HTTP security rows: %w", err)
	}

	return out, nil
}
