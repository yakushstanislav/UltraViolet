package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/masscan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/portscan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmode"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanpolicy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanprofile"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/targetstrategy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/zmap"
)

// openPortStream wraps the ports channel and the wait function so the
// pipeline can drain results and then propagate any fatal backend error.
type openPortStream struct {
	ch   <-chan portscan.OpenPort
	wait func() error
}

func (p *Pipeline) startOpenPortStream(
	ctx context.Context,
	mode scanmode.Mode,
	profile scanprofile.Profile,
	strategy targetstrategy.Strategy,
	cidr string,
	allowedCIDRs string,
	country string,
	ports []uint16,
	limit uint64,
	resumeCursor string,
	cursorUpdate portscan.CursorUpdate,
) (openPortStream, error) {
	switch strategy {
	case targetstrategy.Random:
		return p.startRandomStream(ctx, mode, profile, allowedCIDRs, ports, limit, resumeCursor, cursorUpdate)
	case targetstrategy.Country:
		return p.startCountryStream(ctx, profile, country, ports, limit, resumeCursor, cursorUpdate)
	}

	return p.startSequentialStream(ctx, mode, profile, cidr, ports, limit, resumeCursor, cursorUpdate)
}

// slowScanner returns a portscan.Scanner with the profile's overrides applied
// to the pipeline's base portscan.Config. Stealth (or empty) reuses the
// pre-built scanner so the historical hot path is allocation-free.
func (p *Pipeline) slowScanner(profile scanprofile.Profile) *portscan.Scanner {
	if profile == "" || profile == scanprofile.Stealth {
		return p.scanner
	}

	return portscan.New(profile.Apply(p.config.PortScan))
}

// filterAllowedPrefixes drops every prefix that the scan policy's allow-list
// would reject. When the allow-list is empty (allow-all config) the input is
// returned unchanged.
func filterAllowedPrefixes(policy scanpolicy.Config, prefixes []netip.Prefix) []netip.Prefix {
	if policy.AllowedCIDRs == "" {
		return prefixes
	}

	out := prefixes[:0]

	for _, prefix := range prefixes {
		if policy.IsPrefixAllowed(prefix) {
			out = append(out, prefix)
		}
	}

	return out
}

// startSequentialStream handles sequential strategy for all three engines.
// resumeCursor and cursorUpdate are only honoured by the Slow engine; masscan
// and zmap scan the whole CIDR atomically via subprocess and rely on
// idempotent ingestion to merge re-runs after a pause.
func (p *Pipeline) startSequentialStream(
	ctx context.Context,
	mode scanmode.Mode,
	profile scanprofile.Profile,
	cidr string,
	ports []uint16,
	limit uint64,
	resumeCursor string,
	cursorUpdate portscan.CursorUpdate,
) (openPortStream, error) {
	switch mode {
	case scanmode.Slow:
		targets, err := portscan.EmitCIDR(ctx, cidr, ports, limit, resumeCursor, cursorUpdate)
		if err != nil {
			return openPortStream{}, err
		}

		stream := p.slowScanner(profile).DiscoverFromTargets(ctx, targets)

		return openPortStream{ch: stream.Ports, wait: stream.Wait}, nil

	case scanmode.Masscan:
		d := masscan.New(p.config.Masscan)

		stream, err := d.Discover(ctx, cidr, ports)
		if err != nil {
			return openPortStream{}, err
		}

		return openPortStream{ch: stream.Ports, wait: stream.Wait}, nil

	case scanmode.Zmap:
		d := zmap.New(p.config.Zmap)

		stream, err := d.Discover(ctx, cidr, ports)
		if err != nil {
			return openPortStream{}, err
		}

		return openPortStream{ch: stream.Ports, wait: stream.Wait}, nil

	default:
		return openPortStream{}, fmt.Errorf("unsupported scan mode %q", mode)
	}
}

// startRandomStream handles random strategy for all three engines.
//
// For the slow engine, resumeCursor is parsed as the cumulative emitted-IP
// count so a paused random scan continues sampling instead of restarting;
// an invalid cursor is treated as "start over".
//
// For masscan and zmap the random pool is pre-materialised via
// portscan.SampleRandomIPv4 and handed to the subprocess as a targets
// file; the cursor is ignored (atomic per-job semantics, matching the
// sequential masscan/zmap path).
func (p *Pipeline) startRandomStream(
	ctx context.Context,
	mode scanmode.Mode,
	profile scanprofile.Profile,
	allowedCIDRs string,
	ports []uint16,
	limit uint64,
	resumeCursor string,
	cursorUpdate portscan.CursorUpdate,
) (openPortStream, error) {
	switch mode {
	case scanmode.Slow:
		var alreadyEmitted uint64

		if resumeCursor != "" {
			if n, parseErr := strconv.ParseUint(resumeCursor, 10, 64); parseErr == nil {
				alreadyEmitted = n
			}
		}

		targets, err := portscan.EmitRandom(ctx, allowedCIDRs, ports, limit, alreadyEmitted, cursorUpdate)
		if err != nil {
			return openPortStream{}, err
		}

		stream := p.slowScanner(profile).DiscoverFromTargets(ctx, targets)

		return openPortStream{ch: stream.Ports, wait: stream.Wait}, nil

	case scanmode.Masscan:
		ips, err := portscan.SampleRandomIPv4(ctx, allowedCIDRs, limit)
		if err != nil {
			return openPortStream{}, err
		}

		d := masscan.New(p.config.Masscan)

		stream, err := d.DiscoverIPs(ctx, ips, ports)
		if err != nil {
			return openPortStream{}, err
		}

		return openPortStream{ch: stream.Ports, wait: stream.Wait}, nil

	case scanmode.Zmap:
		ips, err := portscan.SampleRandomIPv4(ctx, allowedCIDRs, limit)
		if err != nil {
			return openPortStream{}, err
		}

		d := zmap.New(p.config.Zmap)

		stream, err := d.DiscoverIPs(ctx, ips, ports)
		if err != nil {
			return openPortStream{}, err
		}

		return openPortStream{ch: stream.Ports, wait: stream.Wait}, nil

	default:
		return openPortStream{}, fmt.Errorf("unsupported scan mode %q", mode)
	}
}

// startCountryStream handles the country strategy (slow engine only). The
// pipeline's GeoIP-derived index is queried for the IPv4 prefixes that the
// MMDB attributes to the requested country, then EmitFromPrefixes samples
// up to limit unique IPs. resumeCursor follows the same decimal cumulative-
// emitted-count convention as random/slow.
func (p *Pipeline) startCountryStream(
	ctx context.Context,
	profile scanprofile.Profile,
	country string,
	ports []uint16,
	limit uint64,
	resumeCursor string,
	cursorUpdate portscan.CursorUpdate,
) (openPortStream, error) {
	if p.countryIndex == nil {
		return openPortStream{}, errors.New("country strategy requires GeoIP country database")
	}

	prefixes := p.countryIndex.Prefixes(country)
	if len(prefixes) == 0 {
		return openPortStream{}, fmt.Errorf("country %q has no IPv4 prefixes in GeoIP database", country)
	}

	// Defence-in-depth: country-strategy IPs must still fall inside the
	// AllowedCIDRs allow-list, just like sequential/random. Without this filter
	// a stray RFC1918 entry in the GeoIP MMDB would let an operator scan
	// internal networks via country=XX even though every other strategy is
	// gated.
	prefixes = filterAllowedPrefixes(p.config.ScanPolicy, prefixes)
	if len(prefixes) == 0 {
		return openPortStream{}, fmt.Errorf(
			"country %q prefixes excluded by SCAN_ALLOWED_CIDRS", country,
		)
	}

	var alreadyEmitted uint64

	if resumeCursor != "" {
		if n, parseErr := strconv.ParseUint(resumeCursor, 10, 64); parseErr == nil {
			alreadyEmitted = n
		}
	}

	targets, err := portscan.EmitFromPrefixes(ctx, prefixes, ports, limit, alreadyEmitted, cursorUpdate)
	if err != nil {
		return openPortStream{}, err
	}

	stream := p.slowScanner(profile).DiscoverFromTargets(ctx, targets)

	return openPortStream{ch: stream.Ports, wait: stream.Wait}, nil
}
