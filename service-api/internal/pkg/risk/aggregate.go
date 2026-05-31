package risk

import "math"

// ServiceRiskResult is the per-service output written to uv_service.
type ServiceRiskResult struct {
	Probability ProbabilityResult
	Confidence  float64
	Score       int32
	Factors     Factors
}

// HostRiskResult is the per-host output written to uv_host.
type HostRiskResult struct {
	P          float64
	I          float64
	Confidence float64
	Score      int32
	Factors    Factors
}

// Factors is the JSON shape persisted in risk_factors columns and returned by
// the risk-explain API. The shape is wire-stable across the API.
type Factors struct {
	Probability      float64          `json:"probability"`
	Impact           float64          `json:"impact,omitempty"`
	Confidence       float64          `json:"confidence"`
	Score            int32            `json:"score"`
	Bucket           string           `json:"bucket"`
	RecencyFactor    float64          `json:"recency_factor,omitempty"`
	Channels         []FactorChannel  `json:"channels,omitempty"`
	Impacts          []FactorImpact   `json:"impacts,omitempty"`
	ConfidenceMeters FactorConfidence `json:"confidence_meters"`
}

// FactorChannel is one probability-channel contribution serialised for the UI.
type FactorChannel struct {
	Code    string   `json:"code"`
	Label   string   `json:"label"`
	P       float64  `json:"p"`
	Sources []string `json:"sources,omitempty"`
}

// FactorImpact is one impact-component contribution serialised for the UI.
type FactorImpact struct {
	Code         string  `json:"code"`
	Label        string  `json:"label"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
}

// FactorConfidence is the per-meter confidence breakdown.
type FactorConfidence struct {
	Completeness    float64 `json:"completeness"`
	Recency         float64 `json:"recency"`
	SignalQuality   float64 `json:"signal_quality"`
	TagCompleteness float64 `json:"tag_completeness"`
}

// AggregateService composes probability + confidence into the final per-service
// score. Impact is not applied per-service in v2 — that is a host-level concept
// — so the service score is 100·(1-exp(-k·P)), useful for ranking individual
// services within a host.
func AggregateService(probability ProbabilityResult, confidence float64, policy Policy) ServiceRiskResult {
	score := computeExpScore(policy.KCoefficient * probability.P)

	channels := make([]FactorChannel, 0, len(probability.Channels))

	for _, channel := range probability.Channels {
		if channel.P <= 0 {
			continue
		}

		channels = append(channels, FactorChannel{
			Code:    string(channel.Code),
			Label:   channel.Label,
			P:       channel.P,
			Sources: channel.Sources,
		})
	}

	factors := Factors{
		Probability:   probability.P,
		Confidence:    confidence,
		Score:         score,
		Bucket:        BucketForScore(score),
		RecencyFactor: probability.RecencyFactor,
		Channels:      channels,
	}

	return ServiceRiskResult{
		Probability: probability,
		Confidence:  confidence,
		Score:       score,
		Factors:     factors,
	}
}

// AggregateHost unions service-level probabilities and applies the host's
// impact + k coefficient, returning the final 0..100 score, the persisted
// factors_v2 payload, and the confidence rolled together.
//
// Service union: P_host = 1 - Π(1 - P_service) up to a 0.99 ceiling. This
// rewards an adversary's parallel attack avenues without ever pinning the
// score above what's mathematically defensible.
func AggregateHost(services []ServiceRiskResult, impact ImpactResult, confidenceInputs ConfidenceInputs, policy Policy) HostRiskResult {
	complement := 1.0

	channelAggregate := make(map[ChannelCode]FactorChannel)

	for _, service := range services {
		p := clamp01(service.Probability.P)
		complement *= 1.0 - p

		for _, channel := range service.Probability.Channels {
			if channel.P <= 0 {
				continue
			}

			existing, ok := channelAggregate[channel.Code]
			if !ok {
				channelAggregate[channel.Code] = FactorChannel{
					Code:    string(channel.Code),
					Label:   channel.Label,
					P:       channel.P,
					Sources: channel.Sources,
				}

				continue
			}

			merged := 1.0 - (1.0-existing.P)*(1.0-channel.P)
			existing.P = merged
			existing.Sources = mergeSources(existing.Sources, channel.Sources)
			channelAggregate[channel.Code] = existing
		}
	}

	pHost := 1.0 - complement
	if pHost > 0.99 {
		pHost = 0.99
	}

	confidence := ComputeConfidence(confidenceInputs)

	score := computeExpScore(policy.KCoefficient * pHost * impact.I)

	impacts := make([]FactorImpact, 0, len(impact.Components))

	for _, component := range impact.Components {
		impacts = append(impacts, FactorImpact(component))
	}

	channels := make([]FactorChannel, 0, len(channelAggregate))

	for _, channel := range channelAggregate {
		channels = append(channels, channel)
	}

	factors := Factors{
		Probability: pHost,
		Impact:      impact.I,
		Confidence:  confidence,
		Score:       score,
		Bucket:      BucketForScore(score),
		Channels:    channels,
		Impacts:     impacts,
		ConfidenceMeters: FactorConfidence{
			Completeness:    confidenceInputs.Completeness,
			Recency:         confidenceInputs.Recency,
			SignalQuality:   confidenceInputs.SignalQuality,
			TagCompleteness: confidenceInputs.TagCompleteness,
		},
	}

	return HostRiskResult{
		P:          pHost,
		I:          impact.I,
		Confidence: confidence,
		Score:      score,
		Factors:    factors,
	}
}

// ClampUnit clamps v into [0, 1]; NaN and negatives collapse to 0.
// Exposed so callers outside this package can share the same clamping
// behaviour without re-implementing it.
func ClampUnit(v float64) float64 {
	return clamp01(v)
}

// computeExpScore maps k·X to a 0..100 integer using the canonical
// Score = round(100·(1-exp(-k·X))) formula. Negative or zero exponents map
// to 0; +inf maps to 100.
func computeExpScore(exponent float64) int32 {
	if math.IsNaN(exponent) || exponent <= 0 {
		return 0
	}

	v := 100.0 * (1.0 - math.Exp(-exponent))

	if v < 0 {
		return 0
	}

	if v > 100 {
		return 100
	}

	return int32(math.Round(v))
}

func mergeSources(a, b []string) []string {
	if len(b) == 0 {
		return a
	}

	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))

	for _, value := range a {
		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}

		out = append(out, value)
	}

	for _, value := range b {
		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}

		out = append(out, value)
	}

	return out
}
