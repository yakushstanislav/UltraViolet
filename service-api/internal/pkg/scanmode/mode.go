// Package scanmode defines the port-discovery engine used during a scan.
//
// This is one axis of scan configuration. The orthogonal axis — how target IP
// addresses are selected — is defined by internal/pkg/targetstrategy.
package scanmode

import (
	"fmt"
)

// Mode selects how open TCP ports are discovered for a scan job.
type Mode string

const (
	// Slow uses the built-in rate-limited TCP connect scanner (accurate, gentle).
	Slow Mode = "slow"
	// Masscan uses the masscan binary for asynchronous discovery (higher throughput).
	Masscan Mode = "masscan"
	// Zmap uses the ZMap binary for asynchronous discovery (higher throughput).
	Zmap Mode = "zmap"
)

// Parse normalizes wire/API values into Mode.
func Parse(s string) (Mode, error) {
	switch Mode(s) {
	case Slow, Masscan, Zmap:
		return Mode(s), nil
	default:
		return "", fmt.Errorf("invalid scan mode %q", s)
	}
}

// String returns the wire form.
func (m Mode) String() string {
	return string(m)
}
