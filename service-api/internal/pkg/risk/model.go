// Package risk holds the pure deterministic scoring core: probability per
// service, host-level impact, host aggregation, confidence, and the canonical
// score formula. The package has no DB dependencies; all inputs are plain
// structs that callers build from repositories.
package risk

// ScoreFromExponent maps k·X to a 0..100 integer using the canonical formula
// Score = round(100·(1 - exp(-k·X))). Negative/NaN inputs collapse to 0;
// the result is clamped to [0,100]. Exposed so the remediation engine and
// the aggregator share a single helper.
func ScoreFromExponent(exponent float64) int32 {
	return computeExpScore(exponent)
}

// Bucket names mirror the UI tier thresholds (low/medium/high/critical) used by
// frontend HostRiskPanel and dashboard aggregations.
const (
	BucketLow      = "low"
	BucketMedium   = "medium"
	BucketHigh     = "high"
	BucketCritical = "critical"
)

// BucketForScore maps a 0..100 score to its bucket label using the same
// thresholds the dashboard applies. Kept here so backend and frontend agree on
// a single source of truth.
func BucketForScore(score int32) string {
	switch {
	case score >= 75:
		return BucketCritical
	case score >= 50:
		return BucketHigh
	case score >= 25:
		return BucketMedium
	default:
		return BucketLow
	}
}
