// Package pivot finds services sharing a correlation artifact.
package pivot

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"

	pivotdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/pivot"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Hit is one service row matching a pivot artifact.
type Hit struct {
	HostID      uint64
	ServiceID   uint64
	IP          string
	Port        uint16
	Transport   string
	Protocol    sql.NullString
	CountryCode sql.NullString
	RiskScore   int32
	Title       sql.NullString
	Total       uint64
}

// Result holds pivot query hits and the total match count.
type Result struct {
	Hits  []Hit
	Total uint64
}

// Repository describes pivot persistence.
type Repository interface {
	FindByArtifact(ctx context.Context, kind, value string, limit uint64) (Result, error)
}

// PostgreSQL implements Repository.
type PostgreSQL struct {
	db pgkit.Querier
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{db: pool}
}

// FindByArtifact returns services sharing the given artifact, ordered by risk.
func (p *PostgreSQL) FindByArtifact(ctx context.Context, kind, value string, limit uint64) (Result, error) {
	if limit == 0 {
		limit = 200
	}

	base := sq.Select(
		"h.id", "svc.id", "host(h.ip)::text",
		"svc.port", "svc.transport", "svc.protocol",
		"h.country_code", "svc.risk_score", "hr.title",
		"COUNT(*) OVER() AS total",
	).
		From("uv_service svc").
		Join("uv_host h ON h.id = svc.host_id").
		LeftJoin("uv_http_response hr ON hr.service_id = svc.id").
		OrderBy("svc.risk_score DESC", "svc.id DESC").
		Limit(limit)

	switch kind {
	case pivotdto.KindTLSFingerprint, pivotdto.KindJARM, pivotdto.KindJA3S, pivotdto.KindJA4S:
		base = base.Join("uv_tls_certificate cert ON cert.service_id = svc.id")

		switch kind {
		case pivotdto.KindTLSFingerprint:
			base = base.Where("cert.fingerprint_sha256 = ?", value)
		case pivotdto.KindJARM:
			base = base.Where("cert.jarm_fingerprint = ?", value)
		case pivotdto.KindJA3S:
			base = base.Where("cert.ja3s_hash = ?", value)
		case pivotdto.KindJA4S:
			base = base.Where("cert.ja4s_hash = ?", value)
		}
	case pivotdto.KindFaviconHash:
		favicon, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return Result{}, fmt.Errorf("can't parse favicon hash: %w", err)
		}

		base = base.Where("hr.favicon_hash = ?", favicon)
	case pivotdto.KindBodySHA256:
		base = base.Where("hr.body_sha256 = ?", value)
	case pivotdto.KindHTTPTitle:
		base = base.Where("hr.title = ?", value)
	default:
		return Result{}, fmt.Errorf("unknown pivot kind %q", kind)
	}

	query, args, err := base.ToSql()
	if err != nil {
		return Result{}, fmt.Errorf("can't build pivot query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return Result{}, fmt.Errorf("can't query pivot hits: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var (
		out   Result
		total uint64
	)

	for rows.Next() {
		var hit Hit

		if err := rows.Scan(
			&hit.HostID, &hit.ServiceID, &hit.IP,
			&hit.Port, &hit.Transport, &hit.Protocol,
			&hit.CountryCode, &hit.RiskScore, &hit.Title,
			&hit.Total,
		); err != nil {
			return Result{}, fmt.Errorf("can't scan pivot hit: %w", pgkit.Handle(err))
		}

		if total == 0 {
			total = hit.Total
		}

		out.Hits = append(out.Hits, hit)
	}

	if err := rows.Err(); err != nil {
		return Result{}, fmt.Errorf("can't iterate pivot hits: %w", err)
	}

	out.Total = total

	return out, nil
}
