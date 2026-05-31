// Package decay holds pure temporal-decay helpers used by the risk model.
//
// Time is always injected (callers pass now and reference timestamps) so the
// helpers stay deterministic and trivially exercisable from the rest of the
// risk package.
package decay

import (
	"math"
	"time"
)

// HalfLifeDecay maps the age of an event to a multiplier in (floor, 1].
//
// At age == 0 the multiplier is 1.0; at age == halfLife it is 0.5; it
// asymptotically decays toward 0 and is clamped to floor so very old evidence
// still carries some weight (a 5-year-old KEV CVE is weaker than last-week's
// but should not vanish entirely).
//
// If halfLife <= 0 the function returns 1.0. If age <= 0 the function returns
// 1.0. floor is clamped to [0, 1].
func HalfLifeDecay(age, halfLife time.Duration, floor float64) float64 {
	if halfLife <= 0 || age <= 0 {
		return 1.0
	}

	if floor < 0 {
		floor = 0
	}

	if floor > 1 {
		floor = 1
	}

	multiplier := math.Pow(0.5, float64(age)/float64(halfLife))

	if multiplier < floor {
		return floor
	}

	return multiplier
}

// LinearDecay maps the age of an event to a multiplier that drops linearly
// from 1.0 to floor across [0, lifetime]. Past lifetime, the multiplier is
// pinned to floor. Useful for "must remediate by N days" countdowns where a
// linear ramp is easier to reason about than an exponential.
func LinearDecay(age, lifetime time.Duration, floor float64) float64 {
	if lifetime <= 0 {
		return 1.0
	}

	if age <= 0 {
		return 1.0
	}

	if floor < 0 {
		floor = 0
	}

	if floor > 1 {
		floor = 1
	}

	if age >= lifetime {
		return floor
	}

	progress := float64(age) / float64(lifetime)

	return 1.0 - (1.0-floor)*progress
}

// Age returns now.Sub(ts) bounded at zero. ts.IsZero() is treated as "unknown",
// returning zero so the caller's decay multiplier collapses to 1.0.
func Age(now, ts time.Time) time.Duration {
	if ts.IsZero() {
		return 0
	}

	d := now.Sub(ts)
	if d < 0 {
		return 0
	}

	return d
}
