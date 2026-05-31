package risk

import (
	"time"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk/decay"
)

// ConfidenceInputs collects the four sub-meters that explain how much we
// trust the host's score. Each is reported back so the UI can render a ring
// + per-meter detail.
type ConfidenceInputs struct {
	Completeness    float64
	Recency         float64
	SignalQuality   float64
	TagCompleteness float64

	UntaggedCap float64
}

// SignalsObserved is what callers fill in to derive Completeness. Each flag
// counts as one "shred" of evidence: more flags true → higher completeness.
type SignalsObserved struct {
	HasBanner      bool
	HasTLS         bool
	HasHTTPHeaders bool
	HasFingerprint bool
	HasCVEMatch    bool
	HasFavicon     bool
}

// CompletenessFrom maps boolean evidence flags to a completeness multiplier.
func CompletenessFrom(signals SignalsObserved) float64 {
	const totalSlots = 6.0

	collected := 0.0
	if signals.HasBanner {
		collected++
	}

	if signals.HasTLS {
		collected++
	}

	if signals.HasHTTPHeaders {
		collected++
	}

	if signals.HasFingerprint {
		collected++
	}

	if signals.HasCVEMatch {
		collected++
	}

	if signals.HasFavicon {
		collected++
	}

	return collected / totalSlots
}

// RecencyFrom collapses the host's most-recent observation timestamp into a
// 0..1 multiplier using the same half-life decay as P.recency.
func RecencyFrom(lastSeen, now time.Time, policy Policy) float64 {
	return decay.HalfLifeDecay(decay.Age(now, lastSeen), policy.RecencyHalfLife, policy.RecencyFloor)
}

// SignalQualityFrom rewards the proportion of probability channels that fired
// on direct evidence (KEV flag set, EPSS > 0, auth state known) versus the
// "unknown / inferred" fallbacks. Both endpoints accept 0..1.
func SignalQualityFrom(directChannels, totalChannels int) float64 {
	if totalChannels <= 0 {
		return 0
	}

	v := float64(directChannels) / float64(totalChannels)

	return clamp01(v)
}

// TagCompletenessFrom maps "tagged with environment + data_sensitivity" to a
// 0..1 multiplier. Hosts missing any business-context tag are capped by
// policy.UntaggedConfidenceCap.
func TagCompletenessFrom(hasEnvironment, hasSensitivity bool) float64 {
	if hasEnvironment && hasSensitivity {
		return 1.0
	}

	if hasEnvironment || hasSensitivity {
		return 0.5
	}

	return 0
}

// ComputeConfidence returns the average of the four sub-meters, capped if
// tag-completeness is missing.
func ComputeConfidence(inputs ConfidenceInputs) float64 {
	sum := clamp01(inputs.Completeness) +
		clamp01(inputs.Recency) +
		clamp01(inputs.SignalQuality) +
		clamp01(inputs.TagCompleteness)

	value := sum / 4.0

	if inputs.TagCompleteness <= 0 && inputs.UntaggedCap > 0 && value > inputs.UntaggedCap {
		value = inputs.UntaggedCap
	}

	return clamp01(value)
}
