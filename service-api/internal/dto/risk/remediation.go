package risk

import "encoding/json"

// Recommendation is the wire shape for one open remediation row.
type Recommendation struct {
	ID                 int64           `json:"id"`
	HostID             uint64          `json:"host_id"`
	ServiceID          *uint64         `json:"service_id,omitempty"`
	ActionCode         string          `json:"action_code"`
	Label              string          `json:"label"`
	ExpectedDeltaP     float64         `json:"expected_delta_p"`
	ExpectedDeltaScore int32           `json:"expected_delta_score"`
	Evidence           json.RawMessage `json:"evidence,omitempty"`
	CreatedAt          string          `json:"created_at"`
	UpdatedAt          string          `json:"updated_at"`
}

// RecommendationsResponse is the wire shape for GET
// /v1/hosts/{ip}/risk-recommendations.
type RecommendationsResponse struct {
	IP              string           `json:"ip"`
	Recommendations []Recommendation `json:"recommendations"`
}
