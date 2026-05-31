package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// UDPProtoFunc gathers UDP protocol-level metadata for a single target.
type UDPProtoFunc func(ctx context.Context, s *Stack, target Target) (*Result, error)

// udpProtoRegistry maps a UDP port to the prober that owns it. Populated by
// init() blocks in the per-protocol files.
var udpProtoRegistry = map[uint16]UDPProtoFunc{}

// RegisterUDP binds fn to one or more UDP ports.
func RegisterUDP(fn UDPProtoFunc, ports ...uint16) {
	if fn == nil {
		panic("probe.RegisterUDP: nil UDPProtoFunc")
	}

	for _, port := range ports {
		if _, dup := udpProtoRegistry[port]; dup {
			panic(fmt.Sprintf("probe.RegisterUDP: duplicate handler for port %d", port))
		}

		udpProtoRegistry[port] = fn
	}
}

// ProbeUDP dispatches to the registered UDP handler for target.Port or
// returns nil when none is registered (UDP has no reliable banner fallback).
func (s *Stack) ProbeUDP(ctx context.Context, target Target) (*Result, error) {
	target.Transport = TransportUDP

	fn, ok := udpProtoRegistry[target.Port]
	if !ok {
		return nil, nil
	}

	return fn(ctx, s, target)
}

// dialUDP opens a connected UDP socket with deadlines applied.
func (s *Stack) dialUDP(ctx context.Context, target Target) (net.Conn, error) {
	timeout := s.probeTimeout(ctx)

	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	dialer := &net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(deadlineFromCtx(ctx, timeout))

	return conn, nil
}
