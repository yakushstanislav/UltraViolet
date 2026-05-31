package risk

import "time"

// Policy holds the tunable weights and decay parameters of the v2 scoring
// model. Constructed once per recompute by the policy service (which loads it
// from uv_risk_policy and caches it) and threaded through every pure call in
// this package.
type Policy struct {
	// KCoefficient is the constant in Score = 100·(1-exp(-k·P·I)).
	KCoefficient float64

	// Impact weights — must sum to <= 1 to keep I_host within [0, 1] before
	// clamping. The aggregate clamps regardless.
	WeightBlast   float64
	WeightLateral float64

	// Temporal decay parameters. HalfLifeDays governs the e^{-ln2·age/HL}
	// rate; floor caps the minimum multiplier so old evidence still counts.
	KEVHalfLife     time.Duration
	EPSSHalfLife    time.Duration
	RecencyHalfLife time.Duration
	TLSHalfLife     time.Duration
	KEVFloor        float64
	EPSSFloor       float64
	RecencyFloor    float64
	TLSFloor        float64

	// UntaggedImpactBaseline is the I_host applied when no asset tags are
	// present on the host; pairs with UntaggedConfidenceCap to express
	// "score is shown but treat it with low confidence".
	UntaggedImpactBaseline float64
	UntaggedConfidenceCap  float64

	// HighRiskThreshold marks the score above which a service counts toward
	// the host-level "broad exposure" factor and dashboard top-risky lists.
	HighRiskThreshold int32
}

// DefaultPolicy returns the seed policy compiled into the binary. The values
// must mirror the row inserted by 5_risk_v2_foundation.up.sql so an unmigrated
// or read-only fallback path produces the same numbers as a freshly-seeded DB.
func DefaultPolicy() Policy {
	return Policy{
		KCoefficient:           4.0,
		WeightBlast:            0.15,
		WeightLateral:          0.20,
		KEVHalfLife:            365 * 24 * time.Hour,
		EPSSHalfLife:           90 * 24 * time.Hour,
		RecencyHalfLife:        30 * 24 * time.Hour,
		TLSHalfLife:            60 * 24 * time.Hour,
		KEVFloor:               0.20,
		EPSSFloor:              0.30,
		RecencyFloor:           0.30,
		TLSFloor:               0.30,
		UntaggedImpactBaseline: 0.40,
		UntaggedConfidenceCap:  0.55,
		HighRiskThreshold:      65,
	}
}
