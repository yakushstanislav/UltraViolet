package portscan

import (
	"context"
	"fmt"
	"net/netip"
)

// CursorUpdate is invoked before each IP is offered to the channel. It is
// called from the emit goroutine, so implementations must not block on the
// channel; throttling is the caller's responsibility. A non-nil error aborts
// emission.
type CursorUpdate func(ctx context.Context, ip string) error

// EmitCIDR walks the prefix lazily and pushes Target messages onto the returned
// channel. The channel is closed when the prefix is exhausted, ctx is done, or
// limit hosts have been emitted (0 = unlimited).
//
// For IPv4 prefixes the network and broadcast addresses are skipped when /31
// is not used (i.e. masks <= /30). IPv6 just emits every address in the prefix.
//
// resumeFrom, when non-empty and parsable as an address inside the prefix,
// makes the walker start from that address instead of the network base. The
// resumeFrom address itself is re-emitted (it may not have been fully scanned
// before the pause); downstream ingestion is idempotent so a duplicate scan
// of one IP is safe.
//
// cursorUpdate, when non-nil, is invoked with the address string just before
// each successful emit, so callers can persist resume state. The callback
// must be cheap (typically a memory store with a separate throttled flusher).
func EmitCIDR(
	ctx context.Context,
	cidr string,
	ports []uint16,
	limit uint64,
	resumeFrom string,
	cursorUpdate CursorUpdate,
) (<-chan Target, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("can't parse CIDR: %w", err)
	}

	startAddr := prefix.Masked().Addr()

	if resumeFrom != "" {
		if resumeAddr, parseErr := netip.ParseAddr(resumeFrom); parseErr == nil && prefix.Contains(resumeAddr) {
			startAddr = resumeAddr
		}
	}

	out := make(chan Target, 64)

	go func() {
		defer close(out)

		addr := startAddr

		skipFirst := prefix.Addr().Is4() && prefix.Bits() < 31
		skipLast := skipFirst

		var emitted uint64

		for prefix.Contains(addr) {
			emit := true

			if skipFirst && addr == prefix.Masked().Addr() {
				emit = false
			}

			if skipLast && isBroadcast(prefix, addr) {
				emit = false
			}

			if emit {
				if cursorUpdate != nil {
					if err := cursorUpdate(ctx, addr.String()); err != nil {
						return
					}
				}

				select {
				case <-ctx.Done():
					return
				case out <- Target{IP: addr, Ports: ports}:
					emitted++
					if limit > 0 && emitted >= limit {
						return
					}
				}
			}

			next := addr.Next()
			if !next.IsValid() {
				return
			}

			addr = next
		}
	}()

	return out, nil
}

func isBroadcast(prefix netip.Prefix, addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}

	bytes := addr.As4()
	mask := prefix.Bits()
	hostBits := 32 - mask

	for i := range hostBits {
		if bytes[3-i/8]&(1<<(i%8)) == 0 {
			return false
		}
	}

	return true
}
