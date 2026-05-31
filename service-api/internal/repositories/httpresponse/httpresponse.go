// Package httpresponse stores HTTP probe snapshots, one row per service.
package httpresponse

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// HTTPResponse is the persisted snapshot of one HTTP probe.
type HTTPResponse struct {
	ServiceID      uint64
	StatusCode     sql.NullInt32
	ServerHeader   sql.NullString
	Title          sql.NullString
	Headers        map[string]string
	Body           sql.NullString
	FaviconHash    sql.NullInt32
	Technologies   []string
	RedirectURL    sql.NullString
	RedirectChain  []RedirectStep
	RobotsTxt      sql.NullString
	SecurityTxt    sql.NullString
	BodySHA256     sql.NullString
	NotFoundHash   sql.NullString
	AltSvcRaw      sql.NullString
	HTTP3Supported bool
	CapturedAt     time.Time
}

// RedirectStep is one hop in the persisted redirect chain.
type RedirectStep struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location,omitempty"`
}

// Repository is the storage contract for HTTP probe responses.
type Repository interface {
	Upsert(ctx context.Context, response *HTTPResponse) error
	GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*HTTPResponse, error)
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

var httpColumns = []string{
	"service_id", "status_code", "server_header", "title", "headers", "body",
	"favicon_hash", "technologies", "redirect_url", "redirect_chain",
	"robots_txt", "security_txt",
	"body_sha256", "not_found_hash", "alt_svc_raw", "http3_supported",
	"captured_at",
}

// listBodyPreviewBytes caps how much of `body` we materialise when fetching
// many services at once (host detail page). A host with hundreds of HTTP
// services × the probe-side default 256 KB body cap would otherwise pull
// hundreds of MB into memory per request. 32 KB is enough for the SPA to
// render a meaningful snippet; the full body stays accessible per-service.
const listBodyPreviewBytes = 32 * 1024

var httpListColumns = []string{
	"service_id", "status_code", "server_header", "title", "headers",
	"LEFT(body, " + strconv.Itoa(listBodyPreviewBytes) + ") AS body",
	"favicon_hash", "technologies", "redirect_url", "redirect_chain",
	"robots_txt", "security_txt",
	"body_sha256", "not_found_hash", "alt_svc_raw", "http3_supported",
	"captured_at",
}

// Upsert inserts or refreshes the HTTP snapshot for the given service.
func (p *PostgreSQL) Upsert(ctx context.Context, response *HTTPResponse) error {
	headersJSON, err := marshalHeaders(response.Headers)
	if err != nil {
		return fmt.Errorf("can't marshal HTTP response headers: %w", err)
	}

	chainJSON, err := marshalRedirectChain(response.RedirectChain)
	if err != nil {
		return fmt.Errorf("can't marshal redirect chain: %w", err)
	}

	capturedAt := response.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}

	query, args, err := sq.Insert("uv_http_response").
		Columns(httpColumns...).
		Values(
			response.ServiceID, response.StatusCode, response.ServerHeader,
			response.Title, headersJSON, response.Body,
			response.FaviconHash, response.Technologies, response.RedirectURL,
			chainJSON, response.RobotsTxt, response.SecurityTxt,
			response.BodySHA256, response.NotFoundHash, response.AltSvcRaw, response.HTTP3Supported,
			capturedAt,
		).
		Suffix(`ON CONFLICT (service_id) DO UPDATE SET
    status_code     = EXCLUDED.status_code,
    server_header   = EXCLUDED.server_header,
    title           = EXCLUDED.title,
    headers         = EXCLUDED.headers,
    body            = EXCLUDED.body,
    favicon_hash    = EXCLUDED.favicon_hash,
    technologies    = EXCLUDED.technologies,
    redirect_url    = EXCLUDED.redirect_url,
    redirect_chain  = EXCLUDED.redirect_chain,
    robots_txt      = EXCLUDED.robots_txt,
    security_txt    = EXCLUDED.security_txt,
    body_sha256     = EXCLUDED.body_sha256,
    not_found_hash  = EXCLUDED.not_found_hash,
    alt_svc_raw     = EXCLUDED.alt_svc_raw,
    http3_supported = EXCLUDED.http3_supported,
    captured_at     = EXCLUDED.captured_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert HTTP response query: %w", err)
	}

	if _, err = p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert HTTP response: %w", pgkit.Handle(err))
	}

	return nil
}

// GetByServiceIDs returns a map of service_id → HTTPResponse for the given ids.
// Service ids without a row simply do not appear in the map.
//
// The `body` field is truncated to listBodyPreviewBytes to keep host-detail
// page memory bounded when a host hosts many HTTP services. Callers that need
// the full body must fetch it per-service.
func (p *PostgreSQL) GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*HTTPResponse, error) {
	out := make(map[uint64]*HTTPResponse, len(serviceIDs))
	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(httpListColumns...).
		From("uv_http_response").
		Where("service_id = ANY(?)", serviceIDs).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get HTTP responses query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query HTTP responses: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var (
			response  HTTPResponse
			headers   []byte
			chainJSON []byte
		)

		err := rows.Scan(
			&response.ServiceID,
			&response.StatusCode,
			&response.ServerHeader,
			&response.Title,
			&headers,
			&response.Body,
			&response.FaviconHash,
			&response.Technologies,
			&response.RedirectURL,
			&chainJSON,
			&response.RobotsTxt,
			&response.SecurityTxt,
			&response.BodySHA256,
			&response.NotFoundHash,
			&response.AltSvcRaw,
			&response.HTTP3Supported,
			&response.CapturedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan HTTP response: %w", pgkit.Handle(err))
		}

		response.Headers, err = unmarshalHeaders(headers)
		if err != nil {
			return nil, fmt.Errorf("can't decode HTTP response headers: %w", err)
		}

		response.RedirectChain, err = unmarshalRedirectChain(chainJSON)
		if err != nil {
			return nil, fmt.Errorf("can't decode redirect chain: %w", err)
		}

		out[response.ServiceID] = &response
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate HTTP responses: %w", err)
	}

	return out, nil
}

func marshalHeaders(headers map[string]string) ([]byte, error) {
	if len(headers) == 0 {
		return []byte("{}"), nil
	}

	return json.Marshal(headers)
}

func unmarshalHeaders(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	headers := map[string]string{}
	if err := json.Unmarshal(raw, &headers); err != nil {
		return nil, err
	}

	return headers, nil
}

func marshalRedirectChain(chain []RedirectStep) ([]byte, error) {
	if len(chain) == 0 {
		return nil, nil
	}

	return json.Marshal(chain)
}

func unmarshalRedirectChain(raw []byte) ([]RedirectStep, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var chain []RedirectStep
	if err := json.Unmarshal(raw, &chain); err != nil {
		return nil, err
	}

	return chain, nil
}
