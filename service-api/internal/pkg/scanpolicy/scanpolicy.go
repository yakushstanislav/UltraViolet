// Package scanpolicy validates scan requests against deployment guardrails.
// It is used by both the HTTP handler layer (at job creation time) and the
// scanner pipeline (at job execution time). For random-strategy scans the CIDR
// is unknown at creation time; use ValidatePorts instead of Validate.
package scanpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	// ErrInvalidCIDR means the requested CIDR cannot be parsed.
	ErrInvalidCIDR = errors.New("invalid CIDR")
	// ErrInvalidPort means the request includes a port outside 1..65535.
	ErrInvalidPort = errors.New("invalid port")
	// ErrTooManyPorts means the request exceeds the configured port limit.
	ErrTooManyPorts = errors.New("too many ports")
	// ErrTooManyHosts means the request exceeds the configured host limit.
	ErrTooManyHosts = errors.New("too many hosts")
	// ErrCIDRNotAllowed means the request is outside the configured allowlist.
	ErrCIDRNotAllowed = errors.New("CIDR not allowed")
)

// Config controls what scan requests are allowed to enter or run in the system.
type Config struct {
	AllowedCIDRs string `env:"SCAN_ALLOWED_CIDRS" env-default:"127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7,fe80::/10"`
	MaxHosts     uint64 `env:"SCAN_MAX_HOSTS"     env-default:"4096"`
	MaxPorts     int    `env:"SCAN_MAX_PORTS"     env-default:"64"`
}

// Validate checks one scan request against CIDR allowlist, host count and port count.
func (c Config) Validate(cidr string, ports []uint16) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrInvalidCIDR)
	}

	prefix = prefix.Masked()

	prefix = unmap4in6(prefix)

	if err := c.validateAllowed(prefix); err != nil {
		return err
	}

	if len(ports) == 0 {
		return ErrInvalidPort
	}

	if c.MaxPorts > 0 && len(ports) > c.MaxPorts {
		return ErrTooManyPorts
	}

	for _, port := range ports {
		if port == 0 {
			return ErrInvalidPort
		}
	}

	hostCount, overflow := CountHosts(prefix)
	if overflow || c.MaxHosts > 0 && hostCount > c.MaxHosts {
		return ErrTooManyHosts
	}

	return nil
}

func (c Config) validateAllowed(target netip.Prefix) error {
	rawAllowed := c.AllowedCIDRs
	if rawAllowed == "" {
		return nil
	}

	for _, raw := range strings.Split(rawAllowed, ",") {
		allowed, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("can't parse allowed CIDR: %w", err)
		}

		if containsPrefix(allowed.Masked(), target) {
			return nil
		}
	}

	return ErrCIDRNotAllowed
}

// IsPrefixAllowed reports whether target is contained in the configured
// allowlist. Returns true when AllowedCIDRs is empty (allow-all config),
// matching validateAllowed semantics. Used by the scanner pipeline to
// filter country-strategy prefixes through the same allow-list that
// gates sequential and random — defence-in-depth against GeoIP data that
// might inadvertently include private/reserved IPv4 ranges.
func (c Config) IsPrefixAllowed(target netip.Prefix) bool {
	return c.validateAllowed(target) == nil
}

func containsPrefix(allowed, target netip.Prefix) bool {
	allowed = unmap4in6(allowed)
	target = unmap4in6(target)

	if allowed.Addr().Is4() != target.Addr().Is4() {
		return false
	}

	return target.Bits() >= allowed.Bits() && allowed.Contains(target.Addr())
}

// unmap4in6 collapses an IPv4-mapped-in-IPv6 prefix down to its IPv4 form so
// the allowlist check cannot be bypassed by sending ::ffff:1.2.3.4 instead of
// 1.2.3.4.
func unmap4in6(p netip.Prefix) netip.Prefix {
	addr := p.Addr()
	if !addr.Is4In6() {
		return p
	}

	v4 := addr.Unmap()

	bits := p.Bits()
	if bits >= 96 {
		bits -= 96
	} else {
		bits = 0
	}

	return netip.PrefixFrom(v4, bits).Masked()
}

// CountHosts returns the number of emitted hosts for a prefix.
//
// It mirrors portscan.EmitCIDR: IPv4 network and broadcast addresses are
// skipped for prefixes wider than /31, while IPv6 emits every address.
func CountHosts(prefix netip.Prefix) (uint64, bool) {
	bits := 128
	if prefix.Addr().Is4() {
		bits = 32
	}

	hostBits := bits - prefix.Bits()
	if hostBits >= 64 {
		return 0, true
	}

	count := uint64(1) << hostBits
	if prefix.Addr().Is4() && prefix.Bits() < 31 {
		count -= 2
	}

	return count, false
}

// ValidatePorts checks only the port list against the configured limits.
// Use this when there is no CIDR to validate (e.g. random strategy).
func (c Config) ValidatePorts(ports []uint16) error {
	if len(ports) == 0 {
		return ErrInvalidPort
	}

	if c.MaxPorts > 0 && len(ports) > c.MaxPorts {
		return ErrTooManyPorts
	}

	for _, port := range ports {
		if port == 0 {
			return ErrInvalidPort
		}
	}

	return nil
}

// ConvertPorts validates signed integer ports and returns uint16 ports.
func ConvertPorts(ports []int32) ([]uint16, error) {
	out := make([]uint16, 0, len(ports))

	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, ErrInvalidPort
		}

		out = append(out, uint16(port))
	}

	return out, nil
}
