// Package service stores observed TCP/UDP services exposed on hosts. Upsert
// records only the observed fields; risk columns (risk_score, probability,
// confidence, risk_factors) are populated by SetRisk after the host risk
// service has scored the row via internal/pkg/risk.
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// ErrNotFound is returned when a service lookup misses.
var ErrNotFound = pgkit.ErrNoRows

// Transport names the wire transport for a service.
type Transport string

const (
	// TransportTCP is the TCP transport.
	TransportTCP Transport = "TCP"
	// TransportUDP is the UDP transport.
	TransportUDP Transport = "UDP"
)

// Service is one observed TCP/UDP service exposed on a host.
type Service struct {
	ID          uint64
	HostID      uint64
	Port        uint16
	Transport   Transport
	Protocol    sql.NullString
	Banner      sql.NullString
	BannerHash  sql.NullString
	LastSeen    time.Time
	RiskScore   int32
	RiskFactors []string
}

// PortBucket is one row of GROUP BY port.
type PortBucket struct {
	Port  uint16
	Count uint64
}

// ProtocolBucket is one row of GROUP BY protocol.
type ProtocolBucket struct {
	Protocol string
	Count    uint64
}

// RiskyService is one row of the top-risky-services aggregate.
type RiskyService struct {
	ServiceID uint64
	HostIP    string
	Port      uint16
	RiskScore int32
	Protocol  sql.NullString
	TopFactor sql.NullString
}

// RiskBucketLabels is the canonical ordered list of score-bucket labels used
// by the dashboard. The same thresholds are applied by RiskBuckets.
var RiskBucketLabels = []string{"low", "medium", "high", "critical"}

// Repository is the storage contract for services.
type Repository interface {
	Upsert(ctx context.Context, service *Service) (uint64, error)
	GetByHostID(ctx context.Context, hostID, limit, offset uint64) ([]*Service, uint64, error)
	// HostHasRTSPOnPort reports whether the host has a service on port with
	// protocol rtsp and the given transport (TCP or UDP).
	HostHasRTSPOnPort(ctx context.Context, hostID uint64, port uint16, transport Transport) (bool, error)
	// HostHasONVIFEligiblePort reports whether the host has a TCP service on
	// port with protocol http, https, or onvif (case-insensitive).
	HostHasONVIFEligiblePort(ctx context.Context, hostID uint64, port uint16) (bool, error)
	Count(ctx context.Context) (uint64, error)
	TopPorts(ctx context.Context, limit uint64) ([]PortBucket, error)
	TopProtocols(ctx context.Context, limit uint64) ([]ProtocolBucket, error)
	TopRiskyServices(ctx context.Context, limit uint64) ([]RiskyService, error)
	RiskBuckets(ctx context.Context) (map[string]uint64, error)
	// HostIDForService returns the host_id owning a service row.
	HostIDForService(ctx context.Context, serviceID uint64) (uint64, error)
	// SetRisk persists the score/probability/confidence/risk_factors fields
	// on a service row.
	SetRisk(ctx context.Context, serviceID uint64, params RiskParams) error
	// ListForHostRisk returns the minimal per-service rows the host
	// aggregator needs to compose ServiceProbabilityInputs (port, protocol,
	// last_seen, current risk_score). CVE/header/auth signals are joined
	// separately in Phase 2.
	ListForHostRisk(ctx context.Context, hostID uint64) ([]HostRiskServiceRow, error)
	// WithTx returns a Repository that routes every query through tx.
	WithTx(tx pgx.Tx) Repository
}

// RiskParams is the input set persisted by SetRisk.
type RiskParams struct {
	Score       int32
	Probability float64
	Confidence  float64
	FactorsJSON []byte
}

// HostRiskServiceRow is the per-service slice ListForHostRisk returns. Empty
// Protocol/Banner is normal and signals "channel collapses to baseline".
type HostRiskServiceRow struct {
	ID          uint64
	Port        uint16
	Transport   Transport
	Protocol    sql.NullString
	LastSeen    time.Time
	LegacyScore int32
	BannerHash  sql.NullString
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

var serviceColumns = []string{
	"id", "host_id", "port", "transport", "protocol", "banner", "banner_hash", "last_seen", "risk_score", "risk_factors",
}

// Upsert inserts the service or refreshes its mutable fields. risk_score and
// risk_factors stay at their last persisted values (or zero on first insert);
// the risk service repopulates them via SetRisk after each ingest pass.
func (p *PostgreSQL) Upsert(ctx context.Context, service *Service) (uint64, error) {
	lastSeen := service.LastSeen
	if lastSeen.IsZero() {
		lastSeen = time.Now().UTC()
	}

	transport := service.Transport
	if transport == "" {
		transport = TransportTCP
	}

	port := int32(service.Port)

	query, args, err := sq.Insert("uv_service").
		Columns("host_id", "port", "transport", "protocol", "banner", "banner_hash", "last_seen").
		Values(
			service.HostID,
			port,
			transport,
			service.Protocol,
			service.Banner,
			service.BannerHash,
			lastSeen,
		).
		Suffix(`ON CONFLICT (host_id, port, transport) DO UPDATE SET
    protocol    = EXCLUDED.protocol,
    banner      = EXCLUDED.banner,
    banner_hash = EXCLUDED.banner_hash,
    last_seen   = EXCLUDED.last_seen
RETURNING id`).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build upsert service query: %w", err)
	}

	var id uint64

	if err := p.db.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("can't upsert service: %w", pgkit.Handle(err))
	}

	return id, nil
}

// GetByHostID returns services attached to hostID, paginated by limit/offset,
// plus the total row count for that host.
func (p *PostgreSQL) GetByHostID(ctx context.Context, hostID, limit, offset uint64) ([]*Service, uint64, error) {
	countSQL, countArgs, err := sq.Select("COUNT(*)").From("uv_service").Where(squirrel.Eq{"host_id": hostID}).ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count host services query: %w", err)
	}

	var total uint64

	err = p.db.QueryRow(ctx, countSQL, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("can't count host services: %w", pgkit.Handle(err))
	}

	if total == 0 {
		return nil, 0, nil
	}

	query, args, err := sq.Select(serviceColumns...).
		From("uv_service").
		Where(squirrel.Eq{"host_id": hostID}).
		OrderBy("port").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build get host services query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't query host services: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	services := make([]*Service, 0, limit)

	for rows.Next() {
		service, err := scanService(rows)
		if err != nil {
			return nil, 0, err
		}

		services = append(services, service)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate host services: %w", err)
	}

	return services, total, nil
}

// HostHasRTSPOnPort reports whether hostID has a service on port with
// protocol rtsp (case-insensitive) and the given transport.
func (p *PostgreSQL) HostHasRTSPOnPort(ctx context.Context, hostID uint64, port uint16, transport Transport) (bool, error) {
	query, args, err := sq.Select("COUNT(*)").
		From("uv_service").
		Where(squirrel.Eq{
			"host_id":   hostID,
			"port":      int32(port),
			"transport": transport,
		}).
		Where(squirrel.Expr("LOWER(COALESCE(protocol, '')) = ?", "rtsp")).
		ToSql()
	if err != nil {
		return false, fmt.Errorf("can't build host rtsp port lookup query: %w", err)
	}

	var n uint64

	if err := p.db.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return false, fmt.Errorf("can't query host rtsp port: %w", pgkit.Handle(err))
	}

	return n > 0, nil
}

// HostHasONVIFEligiblePort reports whether hostID has a TCP service on port
// with protocol http, https, or onvif.
func (p *PostgreSQL) HostHasONVIFEligiblePort(ctx context.Context, hostID uint64, port uint16) (bool, error) {
	query, args, err := sq.Select("COUNT(*)").
		From("uv_service").
		Where(squirrel.Eq{
			"host_id":   hostID,
			"port":      int32(port),
			"transport": TransportTCP,
		}).
		Where(squirrel.Expr("LOWER(COALESCE(protocol, '')) IN (?, ?, ?)", "http", "https", "onvif")).
		ToSql()
	if err != nil {
		return false, fmt.Errorf("can't build host onvif port lookup query: %w", err)
	}

	var n uint64

	if err := p.db.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return false, fmt.Errorf("can't query host onvif-eligible port: %w", pgkit.Handle(err))
	}

	return n > 0, nil
}

// HostIDForService returns the host_id for a service primary key.
func (p *PostgreSQL) HostIDForService(ctx context.Context, serviceID uint64) (uint64, error) {
	query, args, err := sq.Select("host_id").
		From("uv_service").
		Where(squirrel.Eq{"id": serviceID}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build host id for service query: %w", err)
	}

	var hostID uint64

	if err := p.db.QueryRow(ctx, query, args...).Scan(&hostID); err != nil {
		return 0, fmt.Errorf("can't load host id for service: %w", pgkit.Handle(err))
	}

	return hostID, nil
}

// Count returns the total number of services.
func (p *PostgreSQL) Count(ctx context.Context) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").From("uv_service").ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count services query: %w", err)
	}

	var n uint64

	if err := p.db.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("can't count services: %w", pgkit.Handle(err))
	}

	return n, nil
}

// TopPorts returns the most common ports observed across all services.
func (p *PostgreSQL) TopPorts(ctx context.Context, limit uint64) ([]PortBucket, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select("port", "COUNT(*)::bigint").
		From("uv_service").
		GroupBy("port").
		OrderBy("COUNT(*) DESC", "port ASC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top ports query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top ports: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]PortBucket, 0, limit)

	for rows.Next() {
		var (
			port int32
			n    int64
		)

		if err := rows.Scan(&port, &n); err != nil {
			return nil, fmt.Errorf("can't scan port bucket: %w", pgkit.Handle(err))
		}

		if n < 0 {
			n = 0
		}

		out = append(out, PortBucket{
			Port:  uint16(port),
			Count: uint64(n),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate port buckets: %w", err)
	}

	return out, nil
}

// TopProtocols returns the most common protocols observed across all services.
// Services with NULL/empty protocol are excluded.
func (p *PostgreSQL) TopProtocols(ctx context.Context, limit uint64) ([]ProtocolBucket, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select("protocol", "COUNT(*)::bigint").
		From("uv_service").
		Where("protocol IS NOT NULL").
		Where("length(trim(both from protocol)) > 0").
		GroupBy("protocol").
		OrderBy("COUNT(*) DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top protocols query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top protocols: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]ProtocolBucket, 0, limit)

	for rows.Next() {
		var (
			protocol string
			n        int64
		)

		if err := rows.Scan(&protocol, &n); err != nil {
			return nil, fmt.Errorf("can't scan protocol bucket: %w", pgkit.Handle(err))
		}

		if n < 0 {
			n = 0
		}

		out = append(out, ProtocolBucket{
			Protocol: protocol,
			Count:    uint64(n),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate protocol buckets: %w", err)
	}

	return out, nil
}

// TopRiskyServices returns the highest-scoring services, joined with their
// host IP and first contributing risk factor.
func (p *PostgreSQL) TopRiskyServices(ctx context.Context, limit uint64) ([]RiskyService, error) {
	if limit == 0 {
		limit = 10
	}

	query, args, err := sq.Select(
		"svc.id",
		"h.ip::text",
		"svc.port",
		"svc.risk_score",
		"svc.protocol",
		"NULLIF(svc.risk_factors->>0, '')",
	).
		From("uv_service svc").
		Join("uv_host h ON h.id = svc.host_id").
		Where("svc.risk_score > 0").
		OrderBy("svc.risk_score DESC", "svc.id DESC").
		Limit(limit).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build top risky services query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query top risky services: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]RiskyService, 0, limit)

	for rows.Next() {
		var (
			row  RiskyService
			port int32
		)

		err := rows.Scan(
			&row.ServiceID,
			&row.HostIP,
			&port,
			&row.RiskScore,
			&row.Protocol,
			&row.TopFactor,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan risky service: %w", pgkit.Handle(err))
		}

		row.Port = uint16(port)

		out = append(out, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate risky services: %w", err)
	}

	return out, nil
}

// RiskBuckets returns the service-count distribution across RiskBucketLabels.
// Missing buckets are filled in by callers via RiskBucketLabels iteration.
func (p *PostgreSQL) RiskBuckets(ctx context.Context) (map[string]uint64, error) {
	query, args, err := sq.Select(
		`CASE
        WHEN risk_score >= 75 THEN 'critical'
        WHEN risk_score >= 50 THEN 'high'
        WHEN risk_score >= 25 THEN 'medium'
        ELSE 'low'
    END AS bucket`,
		"COUNT(*)::bigint",
	).
		From("uv_service").
		GroupBy("bucket").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build risk buckets query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query risk buckets: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make(map[string]uint64, len(RiskBucketLabels))

	for rows.Next() {
		var (
			bucket string
			n      int64
		)

		if err := rows.Scan(&bucket, &n); err != nil {
			return nil, fmt.Errorf("can't scan risk bucket: %w", pgkit.Handle(err))
		}

		if n < 0 {
			n = 0
		}

		out[bucket] = uint64(n)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate risk buckets: %w", err)
	}

	return out, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

// SetRisk persists the risk columns for one service.
func (p *PostgreSQL) SetRisk(ctx context.Context, serviceID uint64, params RiskParams) error {
	factors := params.FactorsJSON
	if factors == nil {
		factors = []byte("{}")
	}

	query, args, err := sq.Update("uv_service").
		Set("risk_score", params.Score).
		Set("probability", params.Probability).
		Set("confidence", params.Confidence).
		Set("risk_factors", squirrel.Expr("?::jsonb", string(factors))).
		Where(squirrel.Eq{"id": serviceID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build set service risk query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't set service risk: %w", pgkit.Handle(err))
	}

	return nil
}

// ListForHostRisk returns the minimal per-service rows the host risk
// aggregator needs to compose ServiceProbabilityInputs. Heavier joins
// (CVE list, HTTP headers, TLS findings, fingerprint) are issued by the
// aggregator in dedicated queries so this row stays cheap.
func (p *PostgreSQL) ListForHostRisk(ctx context.Context, hostID uint64) ([]HostRiskServiceRow, error) {
	query, args, err := sq.Select(
		"id", "port", "transport", "protocol", "last_seen", "risk_score", "banner_hash",
	).
		From("uv_service").
		Where(squirrel.Eq{"host_id": hostID}).
		OrderBy("port ASC", "id ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list services for host risk query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query services for host risk: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]HostRiskServiceRow, 0, 16)

	for rows.Next() {
		var (
			row  HostRiskServiceRow
			port int32
		)

		if err := rows.Scan(
			&row.ID,
			&port,
			&row.Transport,
			&row.Protocol,
			&row.LastSeen,
			&row.LegacyScore,
			&row.BannerHash,
		); err != nil {
			return nil, fmt.Errorf("can't scan host risk service row: %w", pgkit.Handle(err))
		}

		row.Port = uint16(port)

		out = append(out, row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate host risk service rows: %w", err)
	}

	return out, nil
}

func scanService(row rowScanner) (*Service, error) {
	var (
		service     Service
		port        int32
		factorsJSON []byte
	)

	err := row.Scan(
		&service.ID,
		&service.HostID,
		&port,
		&service.Transport,
		&service.Protocol,
		&service.Banner,
		&service.BannerHash,
		&service.LastSeen,
		&service.RiskScore,
		&factorsJSON,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgkit.ErrNoRows
		}

		return nil, fmt.Errorf("can't scan service: %w", pgkit.Handle(err))
	}

	if len(factorsJSON) > 0 {
		chips, decodeErr := DecodeServiceRiskFactors(factorsJSON)
		if decodeErr != nil {
			return nil, fmt.Errorf("can't unmarshal service risk factors: %w", decodeErr)
		}

		service.RiskFactors = chips
	}

	service.Port = uint16(port)

	return &service, nil
}

// DecodeServiceRiskFactors handles both the legacy ["code1", "code2"] array
// shape and the new {"channels":[{"label":...}]} object written by the
// probability×impact aggregator. New rows surface the per-channel label
// as a chip; rows that match neither shape return a non-nil error so the
// caller can decide between failing the request and logging-and-continuing.
func DecodeServiceRiskFactors(raw []byte) ([]string, error) {
	var legacy []string
	if err := json.Unmarshal(raw, &legacy); err == nil {
		return legacy, nil
	}

	var modern struct {
		Channels []struct {
			Label string `json:"label"`
		} `json:"channels"`
	}

	if err := json.Unmarshal(raw, &modern); err != nil {
		return nil, fmt.Errorf("can't decode service risk factors as legacy or modern shape: %w", err)
	}

	out := make([]string, 0, len(modern.Channels))
	for _, channel := range modern.Channels {
		if channel.Label != "" {
			out = append(out, channel.Label)
		}
	}

	return out, nil
}
