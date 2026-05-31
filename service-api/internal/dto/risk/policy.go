package risk

import (
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// policyShape is the shared field list for PolicyRequest / PolicyResponse —
// the wire shape is identical in both directions, the split only signals
// intent at the API boundary so generated clients see two named types.
type policyShape struct {
	KCoefficient           float64 `json:"k_coefficient"               validate:"gte=0.1,lte=20"`
	WeightBlast            float64 `json:"weight_blast"                validate:"gte=0,lte=1"`
	WeightLateral          float64 `json:"weight_lateral"              validate:"gte=0,lte=1"`
	KEVHalfLifeDays        int     `json:"kev_halflife_days"           validate:"gte=1,lte=3650"`
	EPSSHalfLifeDays       int     `json:"epss_halflife_days"          validate:"gte=1,lte=3650"`
	RecencyHalfLifeDays    int     `json:"recency_halflife_days"       validate:"gte=1,lte=3650"`
	TLSHalfLifeDays        int     `json:"tls_halflife_days"           validate:"gte=1,lte=3650"`
	KEVFloor               float64 `json:"kev_floor"                   validate:"gte=0,lte=1"`
	EPSSFloor              float64 `json:"epss_floor"                  validate:"gte=0,lte=1"`
	RecencyFloor           float64 `json:"recency_floor"               validate:"gte=0,lte=1"`
	TLSFloor               float64 `json:"tls_floor"                   validate:"gte=0,lte=1"`
	UntaggedImpactBaseline float64 `json:"untagged_impact_baseline"    validate:"gte=0,lte=1"`
	UntaggedConfidenceCap  float64 `json:"untagged_confidence_cap"     validate:"gte=0,lte=1"`
	HighRiskThreshold      int32   `json:"high_risk_threshold"         validate:"gte=0,lte=100"`
}

// PolicyRequest is the body of PATCH /v1/risk/policy.
type PolicyRequest policyShape

// IsValid runs validator.v9 against the policy update body.
func (p PolicyRequest) IsValid() error {
	if err := validate.Struct(p); err != nil {
		return fmt.Errorf("can't validate risk policy request: %w", err)
	}

	return nil
}

// PolicyResponse is the wire shape returned by GET /v1/risk/policy and the
// echo of PATCH /v1/risk/policy. Same field set as PolicyRequest — the split
// is purely directional, lets generated clients name the two types
// distinctly and keeps room for future read-only fields (e.g. version).
type PolicyResponse policyShape

// ServiceExplainChannel is one channel contribution in the per-service breakdown.
type ServiceExplainChannel struct {
	Code    string   `json:"code"`
	Label   string   `json:"label"`
	P       float64  `json:"p"`
	Sources []string `json:"sources,omitempty"`
}

// ServiceExplainResponse is the wire shape of GET /v1/services/{id}/risk-explain.
type ServiceExplainResponse struct {
	ServiceID     uint64                  `json:"service_id"`
	HostID        uint64                  `json:"host_id"`
	Port          uint16                  `json:"port"`
	Protocol      string                  `json:"protocol,omitempty"`
	Probability   float64                 `json:"probability"`
	RecencyFactor float64                 `json:"recency_factor"`
	Channels      []ServiceExplainChannel `json:"channels"`
}
