// Package scanprofile defines speed/intensity profiles for the built-in slow
// TCP-connect scanner.
//
// This is a third orthogonal axis of scan configuration alongside
// internal/pkg/scanmode (which engine: slow/masscan/zmap) and
// internal/pkg/targetstrategy (how target IPs are picked). A profile is only
// meaningful when scanmode = Slow; masscan and zmap ignore it.
//
// Stealth preserves the historical gentle behavior (low rate, low
// concurrency). Balanced and Aggressive widen the rate limit and worker pool
// while keeping pure TCP-connect semantics — no raw SYN, the global
// rate.Limiter still throttles every dial.
package scanprofile

import (
	"fmt"
	"time"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/portscan"
)

// Profile selects the speed/intensity preset applied to portscan.Config when
// running a slow-mode scan.
type Profile string

const (
	// Stealth keeps the historical defaults (W=256, R=1000, T=2s, IP=64).
	Stealth Profile = "stealth"
	// Balanced widens the rate limiter and worker pool ~5x (W=1024, R=5000, T=1.5s, IP=128).
	Balanced Profile = "balanced"
	// Aggressive runs close to masscan throughput while staying TCP-connect (W=2048, R=20000, T=750ms, IP=256).
	Aggressive Profile = "aggressive"
)

// Parse normalizes wire/API values into Profile.
func Parse(s string) (Profile, error) {
	switch Profile(s) {
	case Stealth, Balanced, Aggressive:
		return Profile(s), nil
	default:
		return "", fmt.Errorf("invalid scan profile %q", s)
	}
}

// String returns the wire form.
func (p Profile) String() string {
	return string(p)
}

// Apply returns a portscan.Config derived from base with the profile's
// overrides applied. Stealth leaves base untouched so operators can still
// fine-tune the gentle defaults via PORTSCAN_* env vars.
func (p Profile) Apply(base portscan.Config) portscan.Config {
	switch p {
	case Balanced:
		base.Workers = 1024
		base.RatePerSec = 5000
		base.Timeout = 1500 * time.Millisecond
		base.MaxDialsPerIP = 128
	case Aggressive:
		base.Workers = 2048
		base.RatePerSec = 20000
		base.Timeout = 750 * time.Millisecond
		base.MaxDialsPerIP = 256
	case Stealth:
		// keep base untouched
	}

	return base
}
