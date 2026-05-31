// Package service hosts application-layer logic for uv_service rows. The risk
// helpers in this file compose ServiceProbabilityInputs from the supplied
// per-service signals so the pure pkg/risk core stays free of DB types.
package service

import (
	"context"
	"time"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
	riskpolicysvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/policy"
)

// Inputs is the per-service signal bundle assembled by callers (workers, the
// host risk aggregator) before invoking the scorer. Every field is optional;
// zero values collapse the corresponding probability channel.
type Inputs struct {
	ServiceID            uint64
	HostID               uint64
	Port                 uint16
	Protocol             string
	CVEs                 []risk.CVEInput
	Auth                 risk.AuthState
	DefaultCredsObserved bool
	Crypto               risk.CryptoInput
	AppHygiene           risk.AppHygieneInput
	NetworkPosition      float64
	LastSeen             time.Time

	// Confidence components: callers fill in the boolean evidence flags
	// from the relevant repositories so the scorer can shape its
	// confidence sub-meters without re-loading the row sources.
	Signals                      risk.SignalsObserved
	HasEnvTag, HasSensitivityTag bool
}

// ScoringService applies the v2 model to a single service. The host aggregate
// service composes one of these per service before unioning at the host level.
type ScoringService struct {
	policy *riskpolicysvc.Service
}

// NewScoringService builds the per-service scorer.
func NewScoringService(policy *riskpolicysvc.Service) *ScoringService {
	return &ScoringService{policy: policy}
}

// Score returns a ServiceRiskResult ready to persist on uv_service. The
// returned confidence is the per-service rollup; the caller still owns
// host-level confidence computation.
func (s *ScoringService) Score(ctx context.Context, inputs Inputs) risk.ServiceRiskResult {
	policy, priors := s.policy.Get(ctx)

	probability := risk.ComputeServiceProbability(risk.ServiceProbabilityInputs{
		ServiceID:            inputs.ServiceID,
		Port:                 inputs.Port,
		Protocol:             inputs.Protocol,
		CVEs:                 inputs.CVEs,
		Auth:                 inputs.Auth,
		DefaultCredsObserved: inputs.DefaultCredsObserved,
		Crypto:               inputs.Crypto,
		AppHygiene:           inputs.AppHygiene,
		NetworkPosition:      inputs.NetworkPosition,
		LastSeen:             inputs.LastSeen,
		Now:                  time.Now().UTC(),
	}, priors, policy)

	confidence := risk.ComputeConfidence(risk.ConfidenceInputs{
		Completeness:    risk.CompletenessFrom(inputs.Signals),
		Recency:         risk.RecencyFrom(inputs.LastSeen, time.Now().UTC(), policy),
		SignalQuality:   serviceSignalQuality(probability),
		TagCompleteness: risk.TagCompletenessFrom(inputs.HasEnvTag, inputs.HasSensitivityTag),
		UntaggedCap:     policy.UntaggedConfidenceCap,
	})

	return risk.AggregateService(probability, confidence, policy)
}

func serviceSignalQuality(probability risk.ProbabilityResult) float64 {
	if len(probability.Channels) == 0 {
		return 0
	}

	direct := 0

	for _, channel := range probability.Channels {
		if channel.P > 0 {
			direct++
		}
	}

	return risk.SignalQualityFrom(direct, len(probability.Channels))
}
