// Package host stores discovered hosts: IPs and their geo/ASN metadata.
package host

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/timeseries"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// ErrNotFound is returned when a host lookup misses.
var ErrNotFound = pgkit.ErrNoRows

// Host is a single network host observed by the scanner.
type Host struct {
	ID            uint64
	IP            netip.Addr
	CountryCode   *string
	CountryName   *string
	City          *string
	Latitude      *float64
	Longitude     *float64
	ASN           *int64
	ASNOrg        *string
	PtrHostname   *string
	FirstSeen     time.Time
	LastSeen      time.Time
	RiskScore     int32
	Probability   float64
	Impact        float64
	Confidence    float64
	RiskFactors   []byte
	RiskUpdatedAt sql.NullTime
}

// RelatedHost names one peer host that shares a fingerprint with another.
type RelatedHost struct {
	IP          string
	Reason      string
	Value       string
	CountryCode string
}

// Repository describes the host storage contract.
type Repository interface {
	Upsert(ctx context.Context, host *Host) (uint64, error)
	GetByID(ctx context.Context, id uint64) (*Host, error)
	GetByIP(ctx context.Context, ip netip.Addr) (*Host, error)
	Count(ctx context.Context) (uint64, error)
	// GetHostCountByCountry returns host counts grouped by normalized country_code.
	GetHostCountByCountry(ctx context.Context) ([]CountryBucket, error)
	// ListGeoHosts returns recent hosts that have valid latitude/longitude.
	ListGeoHosts(ctx context.Context, limit uint64) ([]GeoHostPoint, error)
	TopASN(ctx context.Context, limit uint64) ([]ASNBucket, error)
	TopRiskyHosts(ctx context.Context, limit uint64, scoreThreshold int32) ([]RiskyHost, error)
	BucketedFirstSeenSince(ctx context.Context, since time.Time, bucket string) (map[time.Time]uint64, error)
	// UpdatePTRHostname sets reverse-DNS hostname for an existing host row.
	UpdatePTRHostname(ctx context.Context, ip netip.Addr, ptr *string) error
	// GetIDsByIPs returns a map of ip-string → host_id for all IPs that exist
	// in uv_host. IPs not found are omitted from the result.
	GetIDsByIPs(ctx context.Context, ips []string) (map[string]uint64, error)
	// ListIPsByIDs returns host_id -> ip for existing hosts in one query.
	ListIPsByIDs(ctx context.Context, ids []uint64) (map[uint64]string, error)
	// ListSANsByIPs returns the deduplicated SAN list per IP, joining
	// uv_host → uv_service → uv_tls_certificate. IPs with no TLS-bearing
	// services are omitted from the result. Used to feed forward-DNS
	// enrichment from certificate hostnames when PTR is absent.
	ListSANsByIPs(ctx context.Context, ips []string) (map[string][]string, error)
	// RelatedByIP returns one paginated window of peer hosts sharing a TLS
	// fingerprint, JARM, or favicon hash with the supplied IP (excluding the
	// IP itself), plus the total count across all pages.
	RelatedByIP(ctx context.Context, ip netip.Addr, page, limit uint64) ([]RelatedHost, uint64, error)
	// GatherRiskInputs aggregates service/CVE signals for host risk scoring.
	GatherRiskInputs(ctx context.Context, hostID uint64, highRiskThreshold int32) (RiskAggregateInputs, error)
	// SetRisk persists the host-level risk fields and atomically returns
	// the score the row held *before* the UPDATE so callers can emit
	// bucket-change events without a TOCTOU race against parallel
	// recomputes. risk_updated_at advances on every call.
	SetRisk(ctx context.Context, hostID uint64, params RiskParams) (int32, error)
	// TopHostsByRiskScore returns hosts ranked by persisted risk_score.
	TopHostsByRiskScore(ctx context.Context, limit uint64) ([]ScoredHost, error)
	// HostRiskBuckets returns host-count distribution across score buckets.
	HostRiskBuckets(ctx context.Context) (map[string]uint64, error)
	// ListHostsNeedingRiskUpdate returns host IDs whose score is stale or missing.
	ListHostsNeedingRiskUpdate(ctx context.Context, limit int) ([]uint64, error)
	// WithTx returns a Repository that routes every query through tx.
	WithTx(tx pgx.Tx) Repository
}

// CountryBucket is one row of GROUP BY country from uv_host.
type CountryBucket struct {
	CountryCode string
	Count       uint64
}

// GeoHostPoint is one host row with coordinates for globe rendering.
type GeoHostPoint struct {
	Latitude    float64
	Longitude   float64
	CountryCode string
}

// ASNBucket is one row of GROUP BY asn from uv_host.
type ASNBucket struct {
	ASN    int64
	ASNOrg sql.NullString
	Count  uint64
}

// RiskyHost is a host annotated with its count of services above a risk threshold.
type RiskyHost struct {
	HostID                uint64
	IP                    string
	CountryCode           sql.NullString
	HighRiskServicesCount uint64
}

// ScoredHost is a host with a persisted aggregate risk score.
type ScoredHost struct {
	HostID      uint64
	IP          string
	CountryCode sql.NullString
	RiskScore   int32
	TopFactor   sql.NullString
}

// RiskAggregateInputs holds one-pass aggregates for host risk scoring.
type RiskAggregateInputs struct {
	MaxServiceRisk       int32
	ServiceCount         int32
	HighRiskServiceCount int32
	KEVCount             int32
	MaxEPSS              sql.NullFloat64
	CriticalCVECount     int32
	LastSeen             time.Time
}

// RiskParams is the input set persisted by SetRisk.
type RiskParams struct {
	Score       int32
	Probability float64
	Impact      float64
	Confidence  float64
	FactorsJSON []byte
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	db pgkit.Querier
}

// NewPostgreSQL builds a new Repository backed by the given pool.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{db: pool}
}

// WithTx returns a Repository instance that routes every query through tx so
// callers can compose multi-statement writes atomically.
func (p *PostgreSQL) WithTx(tx pgx.Tx) Repository {
	return &PostgreSQL{db: tx}
}

var hostColumns = []string{
	"id", "ip::text", "country_code", "country_name", "city",
	"latitude", "longitude", "asn", "asn_org", "ptr_hostname", "first_seen", "last_seen",
	"risk_score", "probability", "impact", "confidence", "risk_factors", "risk_updated_at",
}

// Upsert inserts the host or refreshes its mutable fields.
func (p *PostgreSQL) Upsert(ctx context.Context, host *Host) (uint64, error) {
	now := time.Now().UTC()
	if host.LastSeen.IsZero() {
		host.LastSeen = now
	}

	query, args, err := sq.Insert("uv_host").
		Columns("ip", "country_code", "country_name", "city", "latitude", "longitude", "asn", "asn_org", "first_seen", "last_seen").
		Values(
			host.IP.String(),
			host.CountryCode,
			host.CountryName,
			host.City,
			host.Latitude,
			host.Longitude,
			host.ASN,
			host.ASNOrg,
			host.LastSeen,
			host.LastSeen,
		).
		Suffix(`ON CONFLICT (ip) DO UPDATE SET
    country_code = EXCLUDED.country_code,
    country_name = EXCLUDED.country_name,
    city         = EXCLUDED.city,
    latitude     = EXCLUDED.latitude,
    longitude    = EXCLUDED.longitude,
    asn          = EXCLUDED.asn,
    asn_org      = EXCLUDED.asn_org,
    last_seen    = EXCLUDED.last_seen
RETURNING id`).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build upsert host query: %w", err)
	}

	var id uint64

	if err := p.db.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("can't upsert host: %w", pgkit.Handle(err))
	}

	return id, nil
}

// GetByID returns a host by its primary key.
func (p *PostgreSQL) GetByID(ctx context.Context, id uint64) (*Host, error) {
	query, args, err := sq.Select(hostColumns...).From("uv_host").Where(squirrel.Eq{"id": id}).ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get host by id query: %w", err)
	}

	return scanHost(p.db.QueryRow(ctx, query, args...))
}

// GetByIP returns a host by its IP address.
func (p *PostgreSQL) GetByIP(ctx context.Context, ip netip.Addr) (*Host, error) {
	query, args, err := sq.Select(hostColumns...).From("uv_host").Where(squirrel.Eq{"ip": ip.String()}).ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get host by ip query: %w", err)
	}

	return scanHost(p.db.QueryRow(ctx, query, args...))
}

// Count returns the total number of hosts.
func (p *PostgreSQL) Count(ctx context.Context) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").From("uv_host").ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count hosts query: %w", err)
	}

	var n uint64

	if err := p.db.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count hosts: %w", pgkit.Handle(err))
	}

	return n, nil
}

// GetHostCountByCountry aggregates hosts by trimmed upper country_code.
func (p *PostgreSQL) GetHostCountByCountry(ctx context.Context) ([]CountryBucket, error) {
	query, args, err := sq.Select(
		"upper(trim(both from h.country_code::text)) AS cc",
		"COUNT(*)::bigint",
	).
		From("uv_host h").
		Where("h.country_code IS NOT NULL").
		Where("length(trim(both from h.country_code::text)) > 0").
		GroupBy("cc").
		OrderBy("COUNT(*) DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build host count by country query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't list host counts by country: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []CountryBucket

	for rows.Next() {
		var (
			code string
			n    int64
		)

		if err := rows.Scan(&code, &n); err != nil {
			return nil, fmt.Errorf("can't scan host count by country: %w", pgkit.Handle(err))
		}

		if n < 0 {
			n = 0
		}

		out = append(out, CountryBucket{
			CountryCode: code,
			Count:       uint64(n),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate host counts by country: %w", err)
	}

	return out, nil
}

// ListGeoHosts returns hosts with valid coordinates, most recently seen first.
func (p *PostgreSQL) ListGeoHosts(ctx context.Context, limit uint64) ([]GeoHostPoint, error) {
	if limit == 0 {
		limit = 800
	}

	query, args, err := sq.Select(
		"h.latitude",
		"h.longitude",
		"COALESCE(upper(trim(both from h.country_code::text)), '') AS cc",
	).
		From("uv_host h").
		Where("h.latitude IS NOT NULL").
		Where("h.longitude IS NOT NULL").
		Where("h.latitude >= ?", -90).
		Where("h.latitude <= ?", 90).
		Where("h.longitude >= ?", -180).
		Where("h.longitude <= ?", 180).
		OrderBy("h.last_seen DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list geo hosts query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't list geo hosts: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]GeoHostPoint, 0, limit)

	for rows.Next() {
		var row GeoHostPoint

		if err := rows.Scan(&row.Latitude, &row.Longitude, &row.CountryCode); err != nil {
			return nil, fmt.Errorf("can't scan geo host: %w", pgkit.Handle(err))
		}

		out = append(out, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate geo hosts: %w", err)
	}

	return out, nil
}

// TopASN returns ASN buckets sorted by host count desc, limited.
func (p *PostgreSQL) TopASN(ctx context.Context, limit uint64) ([]ASNBucket, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select("asn", "MAX(asn_org)", "COUNT(*)::bigint").
		From("uv_host").
		Where("asn IS NOT NULL").
		GroupBy("asn").
		OrderBy("COUNT(*) DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top asn query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top asn: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []ASNBucket

	for rows.Next() {
		var (
			asn int64
			org sql.NullString
			n   int64
		)

		if err := rows.Scan(&asn, &org, &n); err != nil {
			return nil, fmt.Errorf("can't scan asn row: %w", pgkit.Handle(err))
		}

		if n < 0 {
			n = 0
		}

		out = append(out, ASNBucket{
			ASN:    asn,
			ASNOrg: org,
			Count:  uint64(n),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate asn rows: %w", err)
	}

	return out, nil
}

// TopRiskyHosts returns hosts ranked by the number of services whose risk_score
// is at or above scoreThreshold. Only hosts with at least one such service
// appear in the result.
func (p *PostgreSQL) TopRiskyHosts(ctx context.Context, limit uint64, scoreThreshold int32) ([]RiskyHost, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select("h.id", "h.ip::text", "h.country_code", "COUNT(*)::bigint").
		From("uv_host h").
		Join("uv_service svc ON svc.host_id = h.id").
		Where("svc.risk_score >= ?", scoreThreshold).
		GroupBy("h.id", "h.ip", "h.country_code").
		OrderBy("COUNT(*) DESC", "h.id DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top risky hosts query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top risky hosts: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []RiskyHost

	for rows.Next() {
		var (
			row RiskyHost
			n   int64
		)

		if err := rows.Scan(&row.HostID, &row.IP, &row.CountryCode, &n); err != nil {
			return nil, fmt.Errorf("can't scan risky host: %w", pgkit.Handle(err))
		}

		if n < 0 {
			n = 0
		}

		row.HighRiskServicesCount = uint64(n)

		out = append(out, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate risky hosts: %w", err)
	}

	return out, nil
}

// BucketedFirstSeenSince returns a histogram of hosts grouped by their
// first_seen timestamp per bucket since the given time.
func (p *PostgreSQL) BucketedFirstSeenSince(ctx context.Context, since time.Time, bucket string) (map[time.Time]uint64, error) {
	query, args, err := sq.Select().
		Column(squirrel.Expr("date_trunc(?, first_seen) AS b", bucket)).
		Column("COUNT(*)::bigint").
		From("uv_host").
		Where("first_seen >= ?", since).
		GroupBy("b").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build bucketed first seen query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query bucketed first seen hosts: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	return timeseries.ReadBucketMap(rows)
}

// GetIDsByIPs returns a map of ip-string → host_id for the given IPs in a
// single query. IPs not found in uv_host are omitted from the result.
func (p *PostgreSQL) GetIDsByIPs(ctx context.Context, ips []string) (map[string]uint64, error) {
	out := make(map[string]uint64, len(ips))

	if len(ips) == 0 {
		return out, nil
	}

	query, args, err := sq.Select("ip::text", "id").
		From("uv_host").
		Where("ip = ANY(?)", ips).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get ids by ips query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query host ids by ips: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var (
			ipStr string
			id    uint64
		)

		if err := rows.Scan(&ipStr, &id); err != nil {
			return nil, fmt.Errorf("can't scan host id row: %w", pgkit.Handle(err))
		}

		prefix, err := netip.ParsePrefix(ipStr)
		if err != nil {
			return nil, fmt.Errorf("can't parse host ip: %w", err)
		}

		out[prefix.Addr().String()] = id
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate host id rows: %w", err)
	}

	return out, nil
}

// ListIPsByIDs returns host_id -> ip for the given host IDs.
func (p *PostgreSQL) ListIPsByIDs(ctx context.Context, ids []uint64) (map[uint64]string, error) {
	out := make(map[uint64]string, len(ids))

	if len(ids) == 0 {
		return out, nil
	}

	query, args, err := sq.Select("id", "host(ip)").
		From("uv_host").
		Where("id = ANY(?)", ids).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list ips by ids query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query ips by ids: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var (
			id uint64
			ip string
		)

		if err := rows.Scan(&id, &ip); err != nil {
			return nil, fmt.Errorf("can't scan host ip row: %w", pgkit.Handle(err))
		}

		out[id] = ip
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate host ip rows: %w", err)
	}

	return out, nil
}

// RelatedByIP returns a paginated window of hosts sharing a TLS fingerprint,
// JARM hash, or favicon hash with the supplied IP. The IP itself is excluded.
// Returns (page items, total matching rows across all pages, error).
func (p *PostgreSQL) RelatedByIP(ctx context.Context, ip netip.Addr, page, limit uint64) ([]RelatedHost, uint64, error) {
	if limit == 0 {
		limit = 100
	}

	if page == 0 {
		page = 1
	}

	offset := (page - 1) * limit

	// The CTE structure (self + 3-arm UNION feeding `related`) is Postgres-specific,
	// so it goes through squirrel.Expr per CLAUDE.md SQL rules. Both COUNT and page
	// queries share the exact same prefix.
	cte := squirrel.Expr(`WITH self AS (
  SELECT id FROM uv_host WHERE ip = ?
), related AS (
  SELECT DISTINCT host(h.ip) AS ip, 'cert_fingerprint' AS reason, c.fingerprint_sha256 AS value,
                  COALESCE(h.country_code, '') AS country_code
  FROM uv_tls_certificate c
  JOIN uv_service s ON s.id = c.service_id
  JOIN uv_host h ON h.id = s.host_id
  WHERE c.fingerprint_sha256 IS NOT NULL
    AND c.fingerprint_sha256 IN (
        SELECT c2.fingerprint_sha256 FROM uv_tls_certificate c2
        JOIN uv_service s2 ON s2.id = c2.service_id
        JOIN uv_host h2 ON h2.id = s2.host_id
        WHERE h2.id = (SELECT id FROM self)
          AND c2.fingerprint_sha256 IS NOT NULL
    )
    AND h.id != (SELECT id FROM self)
  UNION
  SELECT DISTINCT host(h.ip), 'jarm', c.jarm_fingerprint,
                  COALESCE(h.country_code, '')
  FROM uv_tls_certificate c
  JOIN uv_service s ON s.id = c.service_id
  JOIN uv_host h ON h.id = s.host_id
  WHERE c.jarm_fingerprint IS NOT NULL
    AND c.jarm_fingerprint IN (
        SELECT c2.jarm_fingerprint FROM uv_tls_certificate c2
        JOIN uv_service s2 ON s2.id = c2.service_id
        JOIN uv_host h2 ON h2.id = s2.host_id
        WHERE h2.id = (SELECT id FROM self)
          AND c2.jarm_fingerprint IS NOT NULL
    )
    AND h.id != (SELECT id FROM self)
  UNION
  SELECT DISTINCT host(h.ip), 'favicon_hash', hr.favicon_hash::text,
                  COALESCE(h.country_code, '')
  FROM uv_http_response hr
  JOIN uv_service s ON s.id = hr.service_id
  JOIN uv_host h ON h.id = s.host_id
  WHERE hr.favicon_hash IS NOT NULL
    AND hr.favicon_hash IN (
        SELECT hr2.favicon_hash FROM uv_http_response hr2
        JOIN uv_service s2 ON s2.id = hr2.service_id
        JOIN uv_host h2 ON h2.id = s2.host_id
        WHERE h2.id = (SELECT id FROM self)
          AND hr2.favicon_hash IS NOT NULL
    )
    AND h.id != (SELECT id FROM self)
)`, ip.String())

	countSQL, countArgs, err := sq.Select("COUNT(*)").
		PrefixExpr(cte).
		From("related").
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build related hosts count query: %w", err)
	}

	var total uint64

	if err = p.db.QueryRow(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("can't count related hosts: %w", pgkit.Handle(err))
	}

	if total == 0 {
		return nil, 0, nil
	}

	pageSQL, pageArgs, err := sq.Select("ip", "reason", "value", "country_code").
		PrefixExpr(cte).
		From("related").
		OrderBy("ip").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build related hosts page query: %w", err)
	}

	rows, err := p.db.Query(ctx, pageSQL, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't query related hosts: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []RelatedHost

	for rows.Next() {
		var row RelatedHost

		if err := rows.Scan(&row.IP, &row.Reason, &row.Value, &row.CountryCode); err != nil {
			return nil, 0, fmt.Errorf("can't scan related host: %w", pgkit.Handle(err))
		}

		out = append(out, row)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate related hosts: %w", err)
	}

	return out, total, nil
}

// GatherRiskInputs aggregates per-service and CVE signals for one host.
func (p *PostgreSQL) GatherRiskInputs(ctx context.Context, hostID uint64, highRiskThreshold int32) (RiskAggregateInputs, error) {
	builder := sq.Select(
		"COALESCE(MAX(svc.risk_score), 0)::int",
		"COUNT(DISTINCT svc.id)::int",
	).
		Column(squirrel.Expr("COUNT(DISTINCT svc.id) FILTER (WHERE svc.risk_score >= ?)::int", highRiskThreshold)).
		Column("COUNT(sc.kev_added_at) FILTER (WHERE sc.kev_added_at IS NOT NULL)::int").
		Column("MAX(sc.epss_score)").
		Column("COUNT(sc.cve_id) FILTER (WHERE sc.severity = 'CRITICAL')::int").
		Column("MAX(h.last_seen)").
		From("uv_host h").
		LeftJoin("uv_service svc ON svc.host_id = h.id").
		LeftJoin("uv_service_cve sc ON sc.service_id = svc.id").
		Where(squirrel.Eq{"h.id": hostID}).
		GroupBy("h.id")

	query, args, err := builder.ToSql()
	if err != nil {
		return RiskAggregateInputs{}, fmt.Errorf("can't build gather risk inputs query: %w", err)
	}

	var out RiskAggregateInputs

	if err := p.db.QueryRow(ctx, query, args...).Scan(
		&out.MaxServiceRisk,
		&out.ServiceCount,
		&out.HighRiskServiceCount,
		&out.KEVCount,
		&out.MaxEPSS,
		&out.CriticalCVECount,
		&out.LastSeen,
	); err != nil {
		return RiskAggregateInputs{}, fmt.Errorf("can't gather risk inputs: %w", pgkit.Handle(err))
	}

	return out, nil
}

// SetRisk persists the risk columns (score, probability, impact, confidence,
// risk_factors), advances risk_updated_at and returns the previous score so
// callers can detect bucket crossings race-free. The pre-UPDATE read and the
// UPDATE share an advisory transaction lock keyed on host_id to keep two
// parallel recomputes from interleaving.
func (p *PostgreSQL) SetRisk(ctx context.Context, hostID uint64, params RiskParams) (int32, error) {
	factors := params.FactorsJSON
	if factors == nil {
		factors = []byte("{}")
	}

	selectSQL, selectArgs, err := sq.Select("risk_score").
		From("uv_host").
		Where(squirrel.Eq{"id": hostID}).
		Suffix("FOR UPDATE").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build pre-update risk_score query: %w", err)
	}

	updateSQL, updateArgs, err := sq.Update("uv_host").
		Set("risk_score", params.Score).
		Set("probability", params.Probability).
		Set("impact", params.Impact).
		Set("confidence", params.Confidence).
		Set("risk_factors", squirrel.Expr("?::jsonb", string(factors))).
		Set("risk_updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": hostID}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build set host risk query: %w", err)
	}

	pool, ok := p.db.(*pgxpool.Pool)
	if !ok {
		// Already inside a tx (WithTx route) — execute directly; the
		// outer caller owns the transaction boundary.
		var prevScore int32

		if scanErr := p.db.QueryRow(ctx, selectSQL, selectArgs...).Scan(&prevScore); scanErr != nil {
			return 0, fmt.Errorf("can't read previous host risk: %w", pgkit.Handle(scanErr))
		}

		if _, execErr := p.db.Exec(ctx, updateSQL, updateArgs...); execErr != nil {
			return 0, fmt.Errorf("can't set host risk: %w", pgkit.Handle(execErr))
		}

		return prevScore, nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("can't begin set-risk transaction: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	var prevScore int32

	if scanErr := tx.QueryRow(ctx, selectSQL, selectArgs...).Scan(&prevScore); scanErr != nil {
		return 0, fmt.Errorf("can't read previous host risk: %w", pgkit.Handle(scanErr))
	}

	if _, execErr := tx.Exec(ctx, updateSQL, updateArgs...); execErr != nil {
		return 0, fmt.Errorf("can't set host risk: %w", pgkit.Handle(execErr))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return 0, fmt.Errorf("can't commit set-risk transaction: %w", commitErr)
	}

	return prevScore, nil
}

// TopHostsByRiskScore returns hosts with the highest persisted risk_score.
func (p *PostgreSQL) TopHostsByRiskScore(ctx context.Context, limit uint64) ([]ScoredHost, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select(
		"h.id", "h.ip::text", "h.country_code", "h.risk_score",
		"(h.risk_factors->'channels'->0->>'label')",
	).
		From("uv_host h").
		Where("h.risk_score > 0").
		OrderBy("h.risk_score DESC", "h.last_seen DESC", "h.id DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top hosts by risk score query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top hosts by risk score: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []ScoredHost

	for rows.Next() {
		var row ScoredHost

		if err := rows.Scan(&row.HostID, &row.IP, &row.CountryCode, &row.RiskScore, &row.TopFactor); err != nil {
			return nil, fmt.Errorf("can't scan scored host: %w", pgkit.Handle(err))
		}

		out = append(out, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate scored hosts: %w", err)
	}

	return out, nil
}

// HostRiskBuckets returns the host-count distribution across score buckets.
func (p *PostgreSQL) HostRiskBuckets(ctx context.Context) (map[string]uint64, error) {
	query, args, err := sq.Select(
		`CASE
        WHEN risk_score >= 75 THEN 'critical'
        WHEN risk_score >= 50 THEN 'high'
        WHEN risk_score >= 25 THEN 'medium'
        ELSE 'low'
    END AS bucket`,
		"COUNT(*)::bigint",
	).
		From("uv_host").
		GroupBy("bucket").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build host risk buckets query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query host risk buckets: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make(map[string]uint64)

	for rows.Next() {
		var (
			bucket string
			n      int64
		)

		if err := rows.Scan(&bucket, &n); err != nil {
			return nil, fmt.Errorf("can't scan host risk bucket: %w", pgkit.Handle(err))
		}

		if n < 0 {
			n = 0
		}

		out[bucket] = uint64(n)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate host risk buckets: %w", err)
	}

	return out, nil
}

// ListHostsNeedingRiskUpdate returns hosts whose score is missing or stale
// relative to the latest EPSS catalog refresh.
func (p *PostgreSQL) ListHostsNeedingRiskUpdate(ctx context.Context, limit int) ([]uint64, error) {
	if limit <= 0 {
		limit = 500
	}

	query, args, err := sq.Select("h.id").
		From("uv_host h").
		Where(squirrel.Or{
			squirrel.Eq{"h.risk_updated_at": nil},
			squirrel.Expr(`h.risk_updated_at < (
				SELECT MAX(c.epss_scored_at) FROM uv_cve c WHERE c.epss_scored_at IS NOT NULL
			)`),
		}).
		OrderBy("h.id ASC").
		Limit(uint64(limit)).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build hosts needing risk update query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query hosts needing risk update: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]uint64, 0, limit)

	for rows.Next() {
		var id uint64

		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("can't scan host id for risk update: %w", pgkit.Handle(err))
		}

		out = append(out, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate hosts needing risk update: %w", err)
	}

	return out, nil
}

// ListSANsByIPs returns ip → deduplicated SAN list, joining hosts to their
// services' TLS certificates. IPs without any TLS-bearing service are
// omitted. SAN values are returned as stored in uv_tls_certificate.sans;
// no normalization is applied.
func (p *PostgreSQL) ListSANsByIPs(ctx context.Context, ips []string) (map[string][]string, error) {
	out := make(map[string][]string, len(ips))

	if len(ips) == 0 {
		return out, nil
	}

	query, args, err := sq.Select("host(h.ip) AS ip", "c.sans").
		From("uv_tls_certificate c").
		Join("uv_service s ON s.id = c.service_id").
		Join("uv_host h ON h.id = s.host_id").
		Where("h.ip = ANY(?)", ips).
		Where("c.sans IS NOT NULL").
		Where("array_length(c.sans, 1) > 0").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list sans by ips query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query sans by ips: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	dedup := make(map[string]map[string]struct{}, len(ips))

	for rows.Next() {
		var (
			ipStr string
			sans  []string
		)

		if err := rows.Scan(&ipStr, &sans); err != nil {
			return nil, fmt.Errorf("can't scan sans row: %w", pgkit.Handle(err))
		}

		bucket, ok := dedup[ipStr]
		if !ok {
			bucket = map[string]struct{}{}
			dedup[ipStr] = bucket
		}

		for _, san := range sans {
			if san != "" {
				bucket[san] = struct{}{}
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate sans rows: %w", err)
	}

	for ipStr, bucket := range dedup {
		list := make([]string, 0, len(bucket))
		for san := range bucket {
			list = append(list, san)
		}

		out[ipStr] = list
	}

	return out, nil
}

// UpdatePTRHostname updates ptr_hostname for the host with the given IP.
// Missing rows are ignored (host may not be persisted yet).
func (p *PostgreSQL) UpdatePTRHostname(ctx context.Context, ip netip.Addr, ptr *string) error {
	query, args, err := sq.Update("uv_host").
		Set("ptr_hostname", ptr).
		Where(squirrel.Eq{"ip": ip.String()}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update ptr hostname query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update host PTR hostname: %w", pgkit.Handle(err))
	}

	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

// scanHost projects one uv_host row (using hostColumns order) into a *Host.
func scanHost(row rowScanner) (*Host, error) {
	var (
		h     Host
		ipStr string
	)

	err := row.Scan(
		&h.ID,
		&ipStr,
		&h.CountryCode,
		&h.CountryName,
		&h.City,
		&h.Latitude,
		&h.Longitude,
		&h.ASN,
		&h.ASNOrg,
		&h.PtrHostname,
		&h.FirstSeen,
		&h.LastSeen,
		&h.RiskScore,
		&h.Probability,
		&h.Impact,
		&h.Confidence,
		&h.RiskFactors,
		&h.RiskUpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgkit.ErrNoRows
		}

		return nil, fmt.Errorf("can't scan host: %w", pgkit.Handle(err))
	}

	prefix, err := netip.ParsePrefix(ipStr)
	if err != nil {
		return nil, fmt.Errorf("can't parse host ip: %w", err)
	}

	h.IP = prefix.Addr()

	return &h, nil
}
