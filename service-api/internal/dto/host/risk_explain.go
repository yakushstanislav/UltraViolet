package host

import (
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// RiskFactor is one named contributor to a host-level risk score (kept
// for backwards compatibility with the legacy additive format).
type RiskFactor struct {
	Code   string `json:"code"`
	Label  string `json:"label"`
	Weight int32  `json:"weight"`
}

// RiskExplainChannel is one probability-channel contribution.
type RiskExplainChannel struct {
	Code    string   `json:"code"`
	Label   string   `json:"label"`
	P       float64  `json:"p"`
	Sources []string `json:"sources,omitempty"`
}

// RiskExplainImpact is one impact-component contribution.
type RiskExplainImpact struct {
	Code         string  `json:"code"`
	Label        string  `json:"label"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
}

// RiskExplainConfidence is the per-meter confidence breakdown.
type RiskExplainConfidence struct {
	Completeness    float64 `json:"completeness"`
	Recency         float64 `json:"recency"`
	SignalQuality   float64 `json:"signal_quality"`
	TagCompleteness float64 `json:"tag_completeness"`
}

// RiskExplainComponents holds the live aggregates used to derive a host score.
type RiskExplainComponents struct {
	MaxServiceRisk       int32    `json:"max_service_risk"`
	ServiceCount         int32    `json:"service_count"`
	HighRiskServiceCount int32    `json:"high_risk_service_count"`
	KEVCount             int32    `json:"kev_count"`
	MaxEPSS              *float64 `json:"max_epss,omitempty"`
	CriticalCVECount     int32    `json:"critical_cve_count"`
	LastSeen             string   `json:"last_seen"`
}

// RiskExplainResponse is the wire format of GET /v1/hosts/{ip}/risk-explain.
type RiskExplainResponse struct {
	IP               string                `json:"ip"`
	RiskScore        int32                 `json:"risk_score"`
	Probability      float64               `json:"probability"`
	Impact           float64               `json:"impact"`
	Confidence       float64               `json:"confidence"`
	Bucket           string                `json:"bucket"`
	UpdatedAt        string                `json:"updated_at,omitempty"`
	Factors          []RiskFactor          `json:"factors"`
	Channels         []RiskExplainChannel  `json:"channels,omitempty"`
	Impacts          []RiskExplainImpact   `json:"impacts,omitempty"`
	ConfidenceMeters RiskExplainConfidence `json:"confidence_meters"`
	Components       RiskExplainComponents `json:"components"`
}

// IsValid validates risk explain path parameters when used as a DTO wrapper.
func (r RiskExplainResponse) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate risk explain response: %w", err)
	}

	return nil
}

// RiskHistoryPoint is one snapshot row in a host risk timeline.
type RiskHistoryPoint struct {
	CapturedAt  string  `json:"captured_at"`
	Score       int32   `json:"score"`
	Probability float64 `json:"probability"`
	Impact      float64 `json:"impact"`
	Confidence  float64 `json:"confidence"`
}

// RiskHistoryResponse is the wire format of GET /v1/hosts/{ip}/risk-history.
type RiskHistoryResponse struct {
	IP     string             `json:"ip"`
	Points []RiskHistoryPoint `json:"points"`
}
