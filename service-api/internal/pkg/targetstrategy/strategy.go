// Package targetstrategy defines how scan targets (IP addresses) are selected
// from the available address space. It is orthogonal to the port-discovery
// engine chosen via scanmode.Mode.
//
// Sequential — the default behaviour: walk the requested CIDR in ascending
// order, optionally capped by a host limit.
//
// Random — sample IP addresses at random from the deployment's allowed CIDR
// list (SCAN_ALLOWED_CIDRS) until the requested host limit is reached. No
// explicit target CIDR is required. Supported only with engine = slow.
//
// Country — sample IP addresses at random from the IPv4 prefixes that the
// GeoIP country database attributes to a single ISO-3166-1 alpha-2 country
// until the requested host limit is reached. No explicit target CIDR is
// required. Supported only with engine = slow.
package targetstrategy

import (
	"fmt"
)

// Strategy selects how scan targets are drawn from the address space.
type Strategy string

const (
	// Sequential walks the requested CIDR in ascending order (current behaviour).
	Sequential Strategy = "sequential"
	// Random samples IP addresses at random from the allowed CIDR list until
	// the host limit is reached. Requires engine = slow.
	Random Strategy = "random"
	// Country samples IP addresses at random from the IPv4 prefixes that the
	// GeoIP country database attributes to a single country, until the host
	// limit is reached. Requires engine = slow.
	Country Strategy = "country"
)

// Parse normalises wire/API values into Strategy.
func Parse(s string) (Strategy, error) {
	switch Strategy(s) {
	case Sequential, Random, Country:
		return Strategy(s), nil
	default:
		return "", fmt.Errorf("invalid target strategy %q", s)
	}
}

// String returns the wire form.
func (s Strategy) String() string {
	return string(s)
}
