package pivot

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// Pivot kind path segments for GET /v1/pivot/{kind}/{value}.
const (
	KindTLSFingerprint = "tls_fingerprint"
	KindJARM           = "jarm"
	KindJA3S           = "ja3s"
	KindJA4S           = "ja4s"
	KindFaviconHash    = "favicon_hash"
	KindBodySHA256     = "body_sha256"
	KindHTTPTitle      = "http_title"
)

// Request holds parsed pivot query parameters.
type Request struct {
	Kind  string
	Value string
	Limit uint64
}

// IsValid validates kind-specific value formats.
func (r *Request) IsValid() error {
	switch r.Kind {
	case KindTLSFingerprint, KindBodySHA256:
		tmp := struct {
			Value string `validate:"hexadecimal,len=64"`
		}{Value: r.Value}

		if err := validate.Struct(&tmp); err != nil {
			return fmt.Errorf("can't validate pivot request: %w", err)
		}
	case KindJARM:
		tmp := struct {
			Value string `validate:"hexadecimal,len=62"`
		}{Value: r.Value}

		if err := validate.Struct(&tmp); err != nil {
			return fmt.Errorf("can't validate pivot request: %w", err)
		}
	case KindJA3S:
		tmp := struct {
			Value string `validate:"hexadecimal,min=8,max=64"`
		}{Value: r.Value}

		if err := validate.Struct(&tmp); err != nil {
			return fmt.Errorf("can't validate pivot request: %w", err)
		}
	case KindJA4S:
		tmp := struct {
			Value string `validate:"max=64"`
		}{Value: r.Value}

		if err := validate.Struct(&tmp); err != nil {
			return fmt.Errorf("can't validate pivot request: %w", err)
		}
	case KindFaviconHash:
		if _, err := strconv.ParseInt(r.Value, 10, 32); err != nil {
			return fmt.Errorf("can't validate pivot request: favicon_hash must be numeric: %w", err)
		}
	case KindHTTPTitle:
		tmp := struct {
			Value string `validate:"max=512"`
		}{Value: r.Value}

		if err := validate.Struct(&tmp); err != nil {
			return fmt.Errorf("can't validate pivot request: %w", err)
		}
	default:
		return fmt.Errorf("can't validate pivot request: unknown kind %q", r.Kind)
	}

	if r.Limit == 0 {
		r.Limit = 200
	}

	if r.Limit > 500 {
		return errors.New("can't validate pivot request: limit exceeds maximum 500")
	}

	return nil
}

// Node is one vertex in the pivot graph.
type Node struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	IP          string `json:"ip,omitempty"`
	HostID      uint64 `json:"host_id,omitempty"`
	ServiceID   uint64 `json:"service_id,omitempty"`
	Port        uint16 `json:"port,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	RiskScore   int32  `json:"risk_score,omitempty"`
	Title       string `json:"title,omitempty"`
}

// Edge connects two pivot graph nodes.
type Edge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

// Response is the wire format of GET /v1/pivot/{kind}/{value}.
type Response struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Total     uint64 `json:"total"`
	Truncated bool   `json:"truncated"`
	Nodes     []Node `json:"nodes"`
	Edges     []Edge `json:"edges"`
}

// KindLabel returns a short human label for a pivot kind.
func KindLabel(kind string) string {
	switch kind {
	case KindTLSFingerprint:
		return "TLS fingerprint"
	case KindJARM:
		return "JARM"
	case KindJA3S:
		return "JA3S"
	case KindJA4S:
		return "JA4S"
	case KindFaviconHash:
		return "Favicon hash"
	case KindBodySHA256:
		return "Body SHA256"
	case KindHTTPTitle:
		return "HTTP title"
	default:
		return strings.ReplaceAll(kind, "_", " ")
	}
}
