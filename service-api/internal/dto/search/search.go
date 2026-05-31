package search

import (
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// Request contains raw search query parameters.
type Request struct {
	Q              string `json:"q" validate:"omitempty,max=1024"`
	QMode          string `json:"q_mode" validate:"omitempty,oneof=auto fuzzy exact"`
	Port           string `json:"port" validate:"omitempty,numeric"`
	PortFrom       string `json:"port_from" validate:"omitempty,numeric"`
	PortTo         string `json:"port_to" validate:"omitempty,numeric"`
	ASN            string `json:"asn" validate:"omitempty,numeric"`
	Country        string `json:"country" validate:"omitempty,len=2,uppercase"`
	Protocol       string `json:"protocol" validate:"omitempty,max=64"`
	TLSIssuer      string `json:"tls_issuer" validate:"omitempty,max=512"`
	TLSFingerprint string `json:"tls_fingerprint" validate:"omitempty,max=128"`
	TLSSubject     string `json:"tls_subject" validate:"omitempty,max=512"`
	TLSSAN         string `json:"tls_san" validate:"omitempty,max=253"`
	SSH            string `json:"ssh" validate:"omitempty,max=256"`
	SSHFingerprint string `json:"ssh_fingerprint" validate:"omitempty,max=128"`
	SMTP           string `json:"smtp" validate:"omitempty,max=512"`
	DNS            string `json:"dns" validate:"omitempty,max=253"`
	LastSeenFrom   string `json:"last_seen_from" validate:"omitempty,datetime=2006-01-02T15:04:05Z07:00"`
	LastSeenTo     string `json:"last_seen_to" validate:"omitempty,datetime=2006-01-02T15:04:05Z07:00"`
	Sort           string `json:"sort" validate:"omitempty,oneof=latest last_seen risk_score relevance cvss_score"`
	RiskScoreMin   string `json:"risk_score_min" validate:"omitempty,numeric"`
	RiskScoreMax   string `json:"risk_score_max" validate:"omitempty,numeric"`
	HasCVE         string `json:"has_cve" validate:"omitempty,oneof=true false 1 0"`
	CVESeverity    string `json:"cve_severity" validate:"omitempty,max=128"`
	CVEID          string `json:"cve_id" validate:"omitempty,max=32"`
	CVEText        string `json:"cve_text" validate:"omitempty,max=512"`
	JARM           string `json:"jarm" validate:"omitempty,hexadecimal,len=62"`
	JA3S           string `json:"ja3s" validate:"omitempty,hexadecimal,min=8,max=64"`
	JA4S           string `json:"ja4s" validate:"omitempty,max=64"`
	FaviconHash    string `json:"favicon_hash" validate:"omitempty,numeric"`
	BodySHA256     string `json:"body_sha256" validate:"omitempty,hexadecimal,len=64"`
	HTTPTitle      string `json:"http_title" validate:"omitempty,max=512"`
	ConfidenceGTE  string `json:"confidence_gte" validate:"omitempty,numeric"`
}

// IsValid validates raw search query parameters.
func (r *Request) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate search request: %w", err)
	}

	return nil
}

// Response is the wire format of the search endpoint.
type Response struct {
	Page  uint64 `json:"page"`
	Limit uint64 `json:"limit"`
	Total uint64 `json:"total"`
	Hits  []Hit  `json:"hits"`
}

// Hit is a single search result row.
type Hit struct {
	ServiceID    uint64 `json:"service_id"`
	HostID       uint64 `json:"host_id"`
	IP           string `json:"ip"`
	CountryCode  string `json:"country_code,omitempty"`
	ASN          *int64 `json:"asn,omitempty"`
	Port         uint16 `json:"port"`
	Transport    string `json:"transport"`
	Protocol     string `json:"protocol,omitempty"`
	StatusCode   *int32 `json:"status_code,omitempty"`
	ServerHeader string `json:"server,omitempty"`
	Title        string `json:"title,omitempty"`
	Fragment     string `json:"fragment,omitempty"`
	RiskScore    int    `json:"risk_score"`
}
