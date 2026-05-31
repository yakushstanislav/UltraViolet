package dashboard

import (
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// TopRequest is the validated query string for GET /v1/dashboard/top.
type TopRequest struct {
	Limit uint64 `validate:"required,min=1,max=50"`
}

// IsValid runs struct validation on the parsed query.
func (r *TopRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate dashboard top request: %w", err)
	}

	return nil
}

// PortRow is one row of the top-ports list.
type PortRow struct {
	Port  uint16 `json:"port"`
	Count uint64 `json:"count"`
}

// ProtocolRow is one row of the top-protocols list.
type ProtocolRow struct {
	Protocol string `json:"protocol"`
	Count    uint64 `json:"count"`
}

// ASNRow is one row of the top-ASN list.
type ASNRow struct {
	ASN    int64  `json:"asn"`
	ASNOrg string `json:"asn_org,omitempty"`
	Count  uint64 `json:"count"`
}

// TopCountryRow is one row of the top-countries list.
type TopCountryRow struct {
	CountryCode string `json:"country_code"`
	Count       uint64 `json:"count"`
}

// TLSIssuerRow is one row of the top-TLS-issuers list.
type TLSIssuerRow struct {
	Issuer string `json:"issuer"`
	Count  uint64 `json:"count"`
}

// TopResponse is the wire format of GET /v1/dashboard/top.
type TopResponse struct {
	Limit         uint64          `json:"limit"`
	TopPorts      []PortRow       `json:"top_ports"`
	TopProtocols  []ProtocolRow   `json:"top_protocols"`
	TopASN        []ASNRow        `json:"top_asn"`
	TopCountries  []TopCountryRow `json:"top_countries"`
	TopTLSIssuers []TLSIssuerRow  `json:"top_tls_issuers"`
}
