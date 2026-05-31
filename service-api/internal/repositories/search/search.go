// Package search executes cross-table full-text and filter queries.
package search

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Query holds the user-provided search filters.
type Query struct {
	Q              string
	QMode          string
	Port           uint16
	PortFrom       uint16
	PortTo         uint16
	Country        string
	ASN            uint64
	Protocol       string
	TLSIssuer      string
	TLSFingerprint string
	TLSSubject     string
	TLSSAN         string
	SSH            string
	SSHFingerprint string
	SMTP           string
	DNS            string
	LastSeenFrom   time.Time
	LastSeenTo     time.Time
	Sort           string
	RiskScoreMin   *int
	RiskScoreMax   *int
	HasCVE         bool
	CVESeverities  []string
	CVEID          string
	CVEText        string
	JARM           string
	JA3S           string
	JA4S           string
	FaviconHash    string
	BodySHA256     string
	HTTPTitle      string
	ConfidenceMin  *float64 // host confidence >= this
	Offset         uint64
	Limit          uint64
}

// Hit is a single match returned by a search.
type Hit struct {
	ServiceID    uint64
	HostID       uint64
	IP           netip.Addr
	CountryCode  sql.NullString
	ASN          sql.NullInt64
	Port         uint16
	Transport    string
	Protocol     sql.NullString
	RiskScore    int
	StatusCode   sql.NullInt32
	ServerHeader sql.NullString
	Title        sql.NullString
	Fragment     sql.NullString
}

// Repository describes the search contract.
type Repository interface {
	Search(ctx context.Context, q *Query) ([]*Hit, uint64, error)
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL builds a new Repository backed by the given pool.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

const (
	tsHeadlineOpts      = "MaxWords=20, MinWords=5, StartSel=__UV_MATCH_START__, StopSel=__UV_MATCH_END__"
	searchSortRelevance = "relevance"
	searchSortCVSSScore = "cvss_score"
)

const ilikeSubstrMaxLen = 256

func ilikeSubstr(s string) string {
	if len(s) > ilikeSubstrMaxLen {
		s = s[:ilikeSubstrMaxLen]
	}

	escaped := ilikeEscape(s)

	return "%" + escaped + "%"
}

func ilikeEscape(s string) string {
	if !strings.ContainsAny(s, `\%_`) {
		return s
	}

	var b strings.Builder

	b.Grow(len(s))

	for _, r := range s {
		if r == '\\' || r == '%' || r == '_' {
			b.WriteByte('\\')
		}

		b.WriteRune(r)
	}

	return b.String()
}

// isPlainTextQuery returns true when q contains only letters, digits, and spaces —
// i.e. it is safe for websearch_to_tsquery. Queries with dots, brackets, or other
// punctuation (e.g. "Math.min", "jQuery(") must fall back to substring (ILIKE) search
// because tsvector tokenisation splits on those characters and the tsquery never matches.
func isPlainTextQuery(q string) bool {
	for _, r := range q {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' {
			return false
		}
	}

	return true
}

// textSearchResult holds the WHERE condition for free-text q, optional tsquery for
// fragment generation, and whether ranking should use pg_trgm similarity.
type textSearchResult struct {
	condition squirrel.Sqlizer
	tsQuery   string
	fuzzyRank bool
}

func effectiveQMode(qMode string) string {
	if qMode == "" {
		return "auto"
	}

	return qMode
}

// buildTextSearchCondition returns a WHERE condition and metadata for ranking/fragments.
// In auto mode plain text uses websearch_to_tsquery; special characters use trigram %.
// Fuzzy mode always uses trigram; exact mode always uses ILIKE substring match.
func buildTextSearchCondition(q, qMode string) textSearchResult {
	mode := effectiveQMode(qMode)

	switch {
	case mode == "fuzzy":
		return textSearchResult{
			condition: squirrel.Expr("(hr.body % ? OR svc.banner % ?)", q, q),
			fuzzyRank: true,
		}
	case mode == "exact":
		return textSearchResult{
			condition: squirrel.Expr(
				"(hr.body ILIKE ? OR svc.banner ILIKE ?)",
				ilikeSubstr(q), ilikeSubstr(q),
			),
		}
	case mode == "auto" && isPlainTextQuery(q):
		return textSearchResult{
			condition: squirrel.Expr(
				"(hr.body_tsv @@ websearch_to_tsquery('simple', ?) OR svc.banner_tsv @@ websearch_to_tsquery('simple', ?) OR to_tsvector('simple', coalesce(hr.title, '')) @@ websearch_to_tsquery('simple', ?) OR to_tsvector('simple', coalesce(h.asn_org, '')) @@ websearch_to_tsquery('simple', ?))",
				q, q, q, q,
			),
			tsQuery: q,
		}
	default:
		return textSearchResult{
			condition: squirrel.Expr("(hr.body % ? OR svc.banner % ?)", q, q),
			fuzzyRank: true,
		}
	}
}

// needsHTTPJoin reports whether the WHERE clause references uv_http_response
// (full-text or ILIKE search on body/title). Used to add the LeftJoin lazily.
func needsHTTPJoin(q *Query) bool {
	if q.FaviconHash != "" || q.BodySHA256 != "" || q.HTTPTitle != "" {
		return true
	}

	if q.Q == "" {
		return false
	}

	if strings.Contains(q.Q, "/") {
		if _, err := netip.ParsePrefix(q.Q); err == nil {
			return false
		}

		return true
	}

	if _, err := netip.ParseAddr(q.Q); err == nil {
		return false
	}

	return true
}

// needsTLSJoin reports whether the WHERE clause references uv_tls_certificate.
func needsTLSJoin(q *Query) bool {
	return q.TLSIssuer != "" || q.TLSFingerprint != "" || q.TLSSubject != "" || q.TLSSAN != "" ||
		q.JARM != "" || q.JA3S != "" || q.JA4S != ""
}

// buildBase composes the from/join/where clauses shared by Search and Facet.
// Joins to uv_http_response and uv_tls_certificate are added lazily so that
// pure metadata facets (port / country / asn / protocol on a filter that does
// not touch HTTP or TLS) skip those joins entirely.
func (p *PostgreSQL) buildBase(q *Query) (squirrel.SelectBuilder, textSearchResult) {
	base := sq.Select().
		From("uv_service svc").
		Join("uv_host h ON h.id = svc.host_id")

	var textMeta textSearchResult

	if q.Q != "" {
		switch {
		case strings.Contains(q.Q, "/"):
			if prefix, err := netip.ParsePrefix(q.Q); err == nil {
				base = base.Where("h.ip <<= ?::cidr", prefix.String())
			} else {
				textMeta = buildTextSearchCondition(q.Q, q.QMode)
				base = base.Where(textMeta.condition)
			}
		default:
			if addr, err := netip.ParseAddr(q.Q); err == nil {
				base = base.Where("h.ip = ?::inet", addr.String())
			} else {
				textMeta = buildTextSearchCondition(q.Q, q.QMode)
				base = base.Where(textMeta.condition)
			}
		}
	}

	if q.Port != 0 {
		base = base.Where("svc.port = ?", q.Port)
	}

	if q.PortFrom != 0 {
		base = base.Where("svc.port >= ?", q.PortFrom)
	}

	if q.PortTo != 0 {
		base = base.Where("svc.port <= ?", q.PortTo)
	}

	if q.Country != "" {
		base = base.Where("h.country_code = ?", strings.ToUpper(q.Country))
	}

	if q.ASN != 0 {
		base = base.Where("h.asn = ?", q.ASN)
	}

	if q.Protocol != "" {
		base = base.Where("svc.protocol = ?", q.Protocol)
	}

	if q.TLSIssuer != "" {
		base = base.Where("cert.issuer = ?", q.TLSIssuer)
	}

	if q.TLSFingerprint != "" {
		base = base.Where("cert.fingerprint_sha256 = ?", q.TLSFingerprint)
	}

	if q.JARM != "" {
		base = base.Where("cert.jarm_fingerprint = ?", q.JARM)
	}

	if q.JA3S != "" {
		base = base.Where("cert.ja3s_hash = ?", q.JA3S)
	}

	if q.JA4S != "" {
		base = base.Where("cert.ja4s_hash = ?", q.JA4S)
	}

	if q.TLSSubject != "" {
		base = base.Where("cert.subject ILIKE ?", ilikeSubstr(q.TLSSubject))
	}

	if q.TLSSAN != "" {
		base = base.Where("cert.sans_text ILIKE ?", ilikeSubstr(q.TLSSAN))
	}

	if q.DNS != "" {
		pattern := ilikeSubstr(q.DNS)

		base = base.Where(squirrel.Expr(
			"EXISTS (SELECT 1 FROM uv_dns_record d WHERE d.host_id = h.id AND (d.name ILIKE ? OR d.value ILIKE ?))",
			pattern, pattern,
		))
	}

	if q.SSH != "" {
		base = base.Where(squirrel.Expr(
			"EXISTS (SELECT 1 FROM uv_ssh_info s WHERE s.service_id = svc.id AND s.server_version ILIKE ?)",
			ilikeSubstr(q.SSH),
		))
	}

	if q.SSHFingerprint != "" {
		base = base.Where(squirrel.Expr(
			"EXISTS (SELECT 1 FROM uv_ssh_info s WHERE s.service_id = svc.id AND s.host_key_fingerprint = ?)",
			q.SSHFingerprint,
		))
	}

	if q.SMTP != "" {
		base = base.Where(squirrel.Expr(
			"EXISTS (SELECT 1 FROM uv_smtp_info m WHERE m.service_id = svc.id AND m.banner ILIKE ?)",
			ilikeSubstr(q.SMTP),
		))
	}

	if !q.LastSeenFrom.IsZero() {
		base = base.Where("svc.last_seen >= ?", q.LastSeenFrom)
	}

	if !q.LastSeenTo.IsZero() {
		base = base.Where("svc.last_seen <= ?", q.LastSeenTo)
	}

	if q.RiskScoreMin != nil {
		base = base.Where("svc.risk_score >= ?", *q.RiskScoreMin)
	}

	if q.RiskScoreMax != nil {
		base = base.Where("svc.risk_score <= ?", *q.RiskScoreMax)
	}

	if q.ConfidenceMin != nil {
		base = base.Where("h.confidence >= ?", *q.ConfidenceMin)
	}

	if q.FaviconHash != "" {
		base = base.Where("hr.favicon_hash = ?", q.FaviconHash)
	}

	if q.BodySHA256 != "" {
		base = base.Where("hr.body_sha256 = ?", q.BodySHA256)
	}

	if q.HTTPTitle != "" {
		base = base.Where("hr.title = ?", q.HTTPTitle)
	}

	if len(q.CVESeverities) > 0 {
		base = base.Where(squirrel.Expr(
			"EXISTS (SELECT 1 FROM uv_service_cve sc WHERE sc.service_id = svc.id AND sc.severity = ANY(?))",
			q.CVESeverities,
		))
	} else if q.HasCVE {
		base = base.Where(squirrel.Expr(
			"EXISTS (SELECT 1 FROM uv_service_cve sc WHERE sc.service_id = svc.id)",
		))
	}

	if q.CVEID != "" {
		base = base.Where(squirrel.Expr(
			"EXISTS (SELECT 1 FROM uv_service_cve sc WHERE sc.service_id = svc.id AND sc.cve_id ILIKE ?)",
			ilikeSubstr(q.CVEID),
		))
	}

	if q.CVEText != "" {
		base = base.Where(squirrel.Expr(
			"EXISTS (SELECT 1 FROM uv_service_cve sc JOIN uv_cve c ON c.id = sc.cve_id WHERE sc.service_id = svc.id AND c.summary_tsv @@ websearch_to_tsquery('simple', ?))",
			q.CVEText,
		))
	}

	if needsHTTPJoin(q) {
		base = base.LeftJoin("uv_http_response hr ON hr.service_id = svc.id")
	}

	if needsTLSJoin(q) {
		base = base.LeftJoin("uv_tls_certificate cert ON cert.service_id = svc.id")
	}

	return base, textMeta
}

// Search runs the query against the service/host/http_response tables.
//
// When q.Q is non-empty:
//   - if it parses as netip.Prefix (contains "/"), filter hosts with h.ip <<= cidr;
//   - else if it parses as netip.Addr, filter h.ip = inet;
//   - otherwise apply websearch_to_tsquery against body_tsv, banner_tsv, title, and asn_org.
//
// The total count is computed via COUNT(*) OVER() inside the main SELECT so we
// only execute the WHERE clause once. When the requested page is past the last
// row, the window returns no rows; a standalone COUNT(*) is run only in that
// edge case so the client still receives a correct total.
func (p *PostgreSQL) Search(ctx context.Context, q *Query) ([]*Hit, uint64, error) {
	if q.Limit == 0 {
		q.Limit = 100
	}

	base, textMeta := p.buildBase(q)

	if !needsHTTPJoin(q) {
		base = base.LeftJoin("uv_http_response hr ON hr.service_id = svc.id")
	}

	fragmentCol := squirrel.Expr("NULL")
	if textMeta.tsQuery != "" {
		fragmentCol = squirrel.Expr(
			`CASE
			  WHEN hr.body_tsv @@ websearch_to_tsquery('simple', ?)
			    THEN ts_headline('simple', hr.body, websearch_to_tsquery('simple', ?), ?::text)
			  WHEN svc.banner_tsv @@ websearch_to_tsquery('simple', ?)
			    THEN ts_headline('simple', svc.banner, websearch_to_tsquery('simple', ?), ?::text)
			  WHEN to_tsvector('simple', coalesce(hr.title, '')) @@ websearch_to_tsquery('simple', ?)
			    THEN hr.title
			  ELSE h.asn_org
			END`,
			textMeta.tsQuery, textMeta.tsQuery, tsHeadlineOpts,
			textMeta.tsQuery, textMeta.tsQuery, tsHeadlineOpts,
			textMeta.tsQuery,
		)
	}

	var rankCol squirrel.Sqlizer

	switch {
	case textMeta.fuzzyRank && q.Sort == searchSortRelevance:
		rankCol = squirrel.Expr(
			"GREATEST(similarity(coalesce(hr.body, ''), ?), similarity(coalesce(svc.banner, ''), ?)) AS search_rank",
			q.Q, q.Q,
		)
	case textMeta.tsQuery != "" && q.Sort == searchSortRelevance:
		rankCol = squirrel.Expr(
			"ts_rank(coalesce(hr.body_tsv, ''::tsvector) || coalesce(svc.banner_tsv, ''::tsvector), websearch_to_tsquery('simple', ?)) AS search_rank",
			textMeta.tsQuery,
		)
	default:
		rankCol = squirrel.Expr("0::float4 AS search_rank")
	}

	orderBy := "svc.id DESC"

	switch q.Sort {
	case "last_seen":
		orderBy = "svc.last_seen DESC, svc.id DESC"
	case "risk_score":
		orderBy = "svc.risk_score DESC, svc.id DESC"
	case searchSortCVSSScore:
		orderBy = "(SELECT MAX(sc.cvss_score) FROM uv_service_cve sc WHERE sc.service_id = svc.id) DESC NULLS LAST, svc.id DESC"
	case searchSortRelevance:
		if textMeta.tsQuery != "" || textMeta.fuzzyRank {
			orderBy = "search_rank DESC, svc.id DESC"
		}
	}

	mainSQL, mainArgs, err := base.
		Columns(
			"svc.id", "h.id", "h.ip::text", "h.country_code", "h.asn",
			"svc.port", "svc.transport", "svc.protocol", "svc.risk_score",
			"hr.status_code", "hr.server_header", "hr.title",
		).
		Column(fragmentCol).
		Column(rankCol).
		Column("COUNT(*) OVER () AS total_count").
		OrderBy(orderBy).
		Limit(q.Limit).
		Offset(q.Offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build search query: %w", err)
	}

	rows, err := p.pool.Query(ctx, mainSQL, mainArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't run search: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	hits := make([]*Hit, 0, q.Limit)

	var total uint64

	for rows.Next() {
		hit, rowTotal, scanErr := scanHit(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}

		hits = append(hits, hit)
		total = rowTotal
	}

	if iterErr := rows.Err(); iterErr != nil {
		return nil, 0, fmt.Errorf("can't iterate hits: %w", iterErr)
	}

	if len(hits) == 0 && q.Offset > 0 {
		total, err = p.count(ctx, q)
		if err != nil {
			return nil, 0, err
		}
	}

	return hits, total, nil
}

// count runs a standalone COUNT(*) for the filter set. Only used as a fallback
// when COUNT(*) OVER() returns no rows (e.g. paging past the last row).
func (p *PostgreSQL) count(ctx context.Context, q *Query) (uint64, error) {
	base, _ := p.buildBase(q)

	countSQL, countArgs, err := base.Column("COUNT(*)").ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count search hits query: %w", err)
	}

	var total uint64

	if err := p.pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return 0, fmt.Errorf("can't count search hits: %w", pgkit.Handle(err))
	}

	return total, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanHit(row rowScanner) (*Hit, uint64, error) {
	var (
		hit   Hit
		ipStr string
		rank  float64
		total uint64
	)

	err := row.Scan(
		&hit.ServiceID,
		&hit.HostID,
		&ipStr,
		&hit.CountryCode,
		&hit.ASN,
		&hit.Port,
		&hit.Transport,
		&hit.Protocol,
		&hit.RiskScore,
		&hit.StatusCode,
		&hit.ServerHeader,
		&hit.Title,
		&hit.Fragment,
		&rank,
		&total,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("can't scan hit: %w", pgkit.Handle(err))
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(ipStr)
		if prefixErr != nil {
			return nil, 0, fmt.Errorf("can't parse hit ip: %w", err)
		}

		addr = prefix.Addr()
	}

	hit.IP = addr

	return &hit, total, nil
}
