// Package search executes full-text and filter-based service queries.
package search

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	searchdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/search"
	searchrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/search"
)

// allowedCVESeverities is the closed set of CVSS v3 severities we accept on
// the wire. Anything else fails validation.
var allowedCVESeverities = map[string]struct{}{
	"CRITICAL": {},
	"HIGH":     {},
	"MEDIUM":   {},
	"LOW":      {},
	"NONE":     {},
}

// ErrInvalidFilters is returned when the request contains malformed filter values.
var ErrInvalidFilters = errors.New("invalid search filters")

// Service executes host/service search queries.
type Service struct {
	searchRepo searchrepository.Repository
}

// NewService creates a new Service backed by searchRepo.
func NewService(searchRepo searchrepository.Repository) *Service {
	return &Service{searchRepo: searchRepo}
}

// Search runs the query encoded in values and returns a paginated result.
func (s *Service) Search(ctx context.Context, values url.Values, page, limit, offset uint64) (*searchdto.Response, error) {
	query, err := buildQuery(values, limit, offset)
	if err != nil {
		return nil, err
	}

	hits, total, err := s.searchRepo.Search(ctx, query)
	if err != nil {
		return nil, err
	}

	response := &searchdto.Response{
		Page:  page,
		Limit: limit,
		Total: total,
		Hits:  make([]searchdto.Hit, 0, len(hits)),
	}

	for _, hit := range hits {
		dtoHit := searchdto.Hit{
			ServiceID: hit.ServiceID,
			HostID:    hit.HostID,
			IP:        hit.IP.String(),
			Port:      hit.Port,
			Transport: hit.Transport,
		}

		if hit.CountryCode.Valid {
			dtoHit.CountryCode = hit.CountryCode.String
		}

		if hit.ASN.Valid {
			asn := hit.ASN.Int64
			dtoHit.ASN = &asn
		}

		if hit.Protocol.Valid {
			dtoHit.Protocol = hit.Protocol.String
		}

		if hit.StatusCode.Valid {
			code := hit.StatusCode.Int32
			dtoHit.StatusCode = &code
		}

		if hit.ServerHeader.Valid {
			dtoHit.ServerHeader = hit.ServerHeader.String
		}

		if hit.Title.Valid {
			dtoHit.Title = hit.Title.String
		}

		if hit.Fragment.Valid {
			dtoHit.Fragment = hit.Fragment.String
		}

		dtoHit.RiskScore = hit.RiskScore

		response.Hits = append(response.Hits, dtoHit)
	}

	return response, nil
}

// asnQueryParamForValidation strips an optional leading "AS" (any casing) so
// values like "AS15169" satisfy the wire DTO numeric constraint while still
// matching how ASNs are shown in the UI and shared links.
func asnQueryParamForValidation(raw string) string {
	if len(raw) < 2 {
		return raw
	}

	if strings.EqualFold(raw[:2], "as") {
		return raw[2:]
	}

	return raw
}

func buildQuery(values url.Values, limit, offset uint64) (*searchrepository.Query, error) {
	request := &searchdto.Request{
		Q:              values.Get("q"),
		QMode:          values.Get("q_mode"),
		Country:        values.Get("country"),
		Protocol:       values.Get("protocol"),
		TLSIssuer:      values.Get("tls_issuer"),
		TLSFingerprint: values.Get("tls_fingerprint"),
		TLSSubject:     values.Get("tls_subject"),
		TLSSAN:         values.Get("tls_san"),
		SSH:            values.Get("ssh"),
		SSHFingerprint: values.Get("ssh_fingerprint"),
		SMTP:           values.Get("smtp"),
		DNS:            values.Get("dns"),
		Port:           values.Get("port"),
		PortFrom:       values.Get("port_from"),
		PortTo:         values.Get("port_to"),
		ASN:            asnQueryParamForValidation(values.Get("asn")),
		LastSeenFrom:   values.Get("last_seen_from"),
		LastSeenTo:     values.Get("last_seen_to"),
		Sort:           values.Get("sort"),
		RiskScoreMin:   values.Get("risk_score_min"),
		RiskScoreMax:   values.Get("risk_score_max"),
		HasCVE:         values.Get("has_cve"),
		CVESeverity:    values.Get("cve_severity"),
		CVEID:          values.Get("cve_id"),
		CVEText:        values.Get("cve_text"),
		JARM:           values.Get("jarm"),
		JA3S:           values.Get("ja3s"),
		JA4S:           values.Get("ja4s"),
		FaviconHash:    values.Get("favicon_hash"),
		BodySHA256:     values.Get("body_sha256"),
		HTTPTitle:      values.Get("http_title"),
		ConfidenceGTE:  values.Get("confidence_gte"),
	}

	if err := request.IsValid(); err != nil {
		return nil, fmt.Errorf("%s: %w", err.Error(), ErrInvalidFilters)
	}

	query := &searchrepository.Query{
		Q:              request.Q,
		QMode:          request.QMode,
		Country:        request.Country,
		Protocol:       request.Protocol,
		TLSIssuer:      request.TLSIssuer,
		TLSFingerprint: request.TLSFingerprint,
		TLSSubject:     request.TLSSubject,
		TLSSAN:         request.TLSSAN,
		SSH:            request.SSH,
		SSHFingerprint: request.SSHFingerprint,
		SMTP:           request.SMTP,
		DNS:            request.DNS,
		CVEText:        request.CVEText,
		JARM:           request.JARM,
		JA3S:           request.JA3S,
		JA4S:           request.JA4S,
		FaviconHash:    request.FaviconHash,
		BodySHA256:     request.BodySHA256,
		HTTPTitle:      request.HTTPTitle,
		Sort:           request.Sort,
		Offset:         offset,
		Limit:          limit,
	}

	if request.CVEID != "" {
		query.CVEID = strings.ToUpper(request.CVEID)
	}

	if request.Port != "" {
		raw := request.Port

		port, parseErr := strconv.ParseUint(raw, 10, 16)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid port: %w", ErrInvalidFilters)
		}

		query.Port = uint16(port)
	}

	if request.PortFrom != "" {
		raw := request.PortFrom

		port, parseErr := strconv.ParseUint(raw, 10, 16)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid port_from: %w", ErrInvalidFilters)
		}

		query.PortFrom = uint16(port)
	}

	if request.PortTo != "" {
		raw := request.PortTo

		port, parseErr := strconv.ParseUint(raw, 10, 16)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid port_to: %w", ErrInvalidFilters)
		}

		query.PortTo = uint16(port)
	}

	if query.PortFrom != 0 && query.PortTo != 0 && query.PortFrom > query.PortTo {
		return nil, fmt.Errorf("port_from must be <= port_to: %w", ErrInvalidFilters)
	}

	if request.ASN != "" {
		raw := request.ASN

		asn, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid asn: %w", ErrInvalidFilters)
		}

		query.ASN = asn
	}

	if request.LastSeenFrom != "" {
		raw := request.LastSeenFrom

		t, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid last_seen_from: %w", ErrInvalidFilters)
		}

		query.LastSeenFrom = t
	}

	if request.LastSeenTo != "" {
		raw := request.LastSeenTo

		t, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid last_seen_to: %w", ErrInvalidFilters)
		}

		query.LastSeenTo = t
	}

	if request.RiskScoreMin != "" {
		raw := request.RiskScoreMin

		v, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid risk_score_min: %w", ErrInvalidFilters)
		}

		v = clampRiskScore(v)

		query.RiskScoreMin = &v
	}

	if request.RiskScoreMax != "" {
		raw := request.RiskScoreMax

		v, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid risk_score_max: %w", ErrInvalidFilters)
		}

		v = clampRiskScore(v)

		query.RiskScoreMax = &v
	}

	if request.ConfidenceGTE != "" {
		v, parseErr := strconv.ParseFloat(request.ConfidenceGTE, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid confidence_gte: %w", ErrInvalidFilters)
		}

		if v < 0 {
			v = 0
		}

		if v > 1 {
			v = 1
		}

		query.ConfidenceMin = &v
	}

	if strings.EqualFold(request.HasCVE, "true") || request.HasCVE == "1" {
		query.HasCVE = true
	}

	if request.CVESeverity != "" {
		parts := strings.Split(request.CVESeverity, ",")
		clean := make([]string, 0, len(parts))

		for _, p := range parts {
			candidate := strings.ToUpper(strings.TrimSpace(p))
			if candidate == "" {
				continue
			}

			if _, ok := allowedCVESeverities[candidate]; !ok {
				return nil, fmt.Errorf("invalid cve_severity: %w", ErrInvalidFilters)
			}

			clean = append(clean, candidate)
		}

		if len(clean) > 0 {
			query.CVESeverities = clean
			query.HasCVE = true
		}
	}

	return query, nil
}

// clampRiskScore pins a parsed risk-score filter into the [0,100] band that
// the rest of the system uses. A wildly out-of-range value isn't a security
// issue (Squirrel parameterises it), but it bloats query logs and makes
// downstream "what filter was applied" telemetry harder to reason about.
func clampRiskScore(v int) int {
	if v < 0 {
		return 0
	}

	if v > 100 {
		return 100
	}

	return v
}
