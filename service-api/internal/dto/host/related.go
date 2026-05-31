package host

import (
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// RelatedHost is one peer host linked by a shared fingerprint.
type RelatedHost struct {
	IP          string `json:"ip"`
	Reason      string `json:"reason"`
	Value       string `json:"value"`
	CountryCode string `json:"country_code,omitempty"`
}

// RelatedHostsRequest is the parsed query string for GET /v1/hosts/{ip}/related.
// Defaults are applied by the handler before validation, so the validator sees
// concrete values (page>=1, 1<=limit<=100) and rejects explicit page=0 / limit=0.
type RelatedHostsRequest struct {
	Page  uint64 `json:"page"  validate:"min=1"`
	Limit uint64 `json:"limit" validate:"min=1,max=100"`
}

// IsValid validates the related hosts query parameters.
func (r RelatedHostsRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate related hosts request: %w", err)
	}

	return nil
}

// RelatedHostsResponse is the JSON body for GET /v1/hosts/{ip}/related.
type RelatedHostsResponse struct {
	Items []RelatedHost `json:"items"`
	Page  uint64        `json:"page"`
	Limit uint64        `json:"limit"`
	Total uint64        `json:"total"`
}
