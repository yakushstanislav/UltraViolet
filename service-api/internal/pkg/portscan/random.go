package portscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
)

// EmitRandom samples up to limit unique IPv4 addresses from the given list of
// allowed CIDR strings and pushes them as Target messages onto the returned
// channel. The channel is closed when limit hosts have been emitted or ctx is
// done.
//
// Only IPv4 prefixes are sampled; IPv6 entries in allowedCIDRs are silently
// skipped. Network and broadcast addresses are excluded (same rules as EmitCIDR).
//
// Deduplication is handled via an in-memory set; for large limits relative to
// the allowlist size this degrades (birthday paradox), so callers should ensure
// limit ≤ 50 % of total address space.
//
// alreadyEmitted lets a resumed random scan continue sampling instead of
// restarting: the effective limit is reduced by that count, the cursor
// callback is invoked with the new cumulative count after each emit, and
// uniqueness across pause boundaries is best-effort (the seen-set is fresh on
// resume so a previously-sampled IP may be re-scanned — ingestion is
// idempotent so it merges).
func EmitRandom(
	ctx context.Context,
	allowedCIDRs string,
	ports []uint16,
	limit uint64,
	alreadyEmitted uint64,
	cursorUpdate CursorUpdate,
) (<-chan Target, error) {
	prefixes, err := parseAllowedCIDRs(allowedCIDRs)
	if err != nil {
		return nil, err
	}

	if len(prefixes) == 0 {
		return nil, errors.New("no usable IPv4 prefixes found in allowed CIDRs")
	}

	return EmitFromPrefixes(ctx, prefixes, ports, limit, alreadyEmitted, cursorUpdate)
}

// EmitFromPrefixes is the shared random-sampling emitter used by both the
// random (SCAN_ALLOWED_CIDRS-driven) and country (GeoIP-driven) strategies.
// Callers must pre-filter the prefix list to IPv4 entries; an empty list is
// rejected. Behaviour mirrors EmitRandom: up to limit unique IPs are sampled,
// alreadyEmitted seeds the cursor for resume, and the channel is closed when
// the limit (or the attempt cap) is reached or ctx is done.
func EmitFromPrefixes(
	ctx context.Context,
	prefixes []netip.Prefix,
	ports []uint16,
	limit uint64,
	alreadyEmitted uint64,
	cursorUpdate CursorUpdate,
) (<-chan Target, error) {
	if limit == 0 {
		return nil, errors.New("limit must be > 0 for random sampling")
	}

	if len(prefixes) == 0 {
		return nil, errors.New("no IPv4 prefixes provided for random sampling")
	}

	remaining := limit
	if alreadyEmitted >= limit {
		remaining = 0
	} else {
		remaining = limit - alreadyEmitted
	}

	// Guard against requesting more IPs than the prefix list can provide. We
	// cap attempts at limit*10 to prevent spinning when the universe is
	// smaller than the requested limit.
	maxAttempts := remaining * 10
	if maxAttempts < 1000 {
		maxAttempts = 1000
	}

	out := make(chan Target, 64)

	go func() {
		defer close(out)

		if remaining == 0 {
			return
		}

		seen := make(map[netip.Addr]struct{}, int(remaining))

		var attempts uint64

		emittedTotal := alreadyEmitted

		for uint64(len(seen)) < remaining {
			if ctx.Err() != nil {
				return
			}

			if attempts >= maxAttempts {
				return
			}

			attempts++

			ip := randomIPFromPrefixes(prefixes)
			if !ip.IsValid() {
				continue
			}

			if _, dup := seen[ip]; dup {
				continue
			}

			seen[ip] = struct{}{}

			if cursorUpdate != nil {
				next := emittedTotal + 1

				if err := cursorUpdate(ctx, strconv.FormatUint(next, 10)); err != nil {
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			case out <- Target{IP: ip, Ports: ports}:
				emittedTotal++
			}
		}
	}()

	return out, nil
}

// SampleRandomIPv4 returns up to limit unique IPv4 addresses sampled
// uniformly from the IPv4 prefixes in allowedCIDRs. It uses the same
// deduplication and exclusion rules as EmitRandom (network and broadcast
// addresses skipped for prefixes wider than /31), but returns a
// materialised slice instead of streaming through a channel.
//
// It exists for engines that need the full target list up front (masscan,
// zmap) — they cannot consume a Go channel and instead read targets from
// a file passed via a CLI flag.
//
// Like EmitRandom, deduplication is in-memory: callers should ensure
// limit ≤ 50 % of the total addressable space to avoid birthday-paradox
// slowdown. The attempt budget is capped at limit*10 (min 1000) to bound
// the worst case when the allowlist is smaller than the requested limit.
func SampleRandomIPv4(ctx context.Context, allowedCIDRs string, limit uint64) ([]netip.Addr, error) {
	if limit == 0 {
		return nil, errors.New("limit must be > 0 for random strategy")
	}

	prefixes, err := parseAllowedCIDRs(allowedCIDRs)
	if err != nil {
		return nil, err
	}

	if len(prefixes) == 0 {
		return nil, errors.New("no usable IPv4 prefixes found in allowed CIDRs")
	}

	maxAttempts := limit * 10
	if maxAttempts < 1000 {
		maxAttempts = 1000
	}

	seen := make(map[netip.Addr]struct{}, int(limit))
	out := make([]netip.Addr, 0, int(limit))

	var attempts uint64

	for uint64(len(out)) < limit {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if attempts >= maxAttempts {
			break
		}

		attempts++

		ip := randomIPFromPrefixes(prefixes)
		if !ip.IsValid() {
			continue
		}

		if _, dup := seen[ip]; dup {
			continue
		}

		seen[ip] = struct{}{}
		out = append(out, ip)
	}

	if len(out) == 0 {
		return nil, errors.New("random sampling produced no IPs from the allowlist")
	}

	return out, nil
}

// parseAllowedCIDRs splits the comma-separated CIDR string and returns parsed
// IPv4 prefixes.
func parseAllowedCIDRs(raw string) ([]netip.Prefix, error) {
	if raw == "" {
		return nil, errors.New("allowed CIDRs is empty")
	}

	parts := strings.Split(raw, ",")
	out := make([]netip.Prefix, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("can't parse allowed CIDR %q: %w", part, err)
		}

		prefix = prefix.Masked()

		if !prefix.Addr().Is4() {
			continue
		}

		out = append(out, prefix)
	}

	return out, nil
}

// randomIPFromPrefixes picks a uniformly random IPv4 address from a random
// prefix in the list, excluding network and broadcast addresses for prefixes
// wider than /31.
func randomIPFromPrefixes(prefixes []netip.Prefix) netip.Addr {
	prefix := prefixes[rand.IntN(len(prefixes))]

	bits := prefix.Bits()
	hostBits := 32 - bits

	base := addr4ToUint32(prefix.Masked().Addr())

	if hostBits == 0 {
		return uint32ToAddr4(base)
	}

	// Use uint64 to avoid overflow when hostBits == 32 (a /0 prefix).
	size := uint64(1) << hostBits

	var lo, hi uint64

	if bits < 31 {
		lo = 1
		hi = size - 2
	} else {
		lo = 0
		hi = size - 1
	}

	if hi < lo {
		return netip.Addr{}
	}

	spread := hi - lo + 1
	if spread > math.MaxInt64 {
		spread = math.MaxInt64
	}

	offset := uint64(rand.Int64N(int64(spread))) + lo

	return uint32ToAddr4(base + uint32(offset))
}

func addr4ToUint32(a netip.Addr) uint32 {
	b := a.As4()

	return binary.BigEndian.Uint32(b[:])
}

func uint32ToAddr4(n uint32) netip.Addr {
	var b [4]byte

	binary.BigEndian.PutUint32(b[:], n)

	return netip.AddrFrom4(b)
}
