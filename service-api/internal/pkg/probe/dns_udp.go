package probe

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

func init() {
	RegisterUDP(probeDNSUDP, 53)
}

// probeDNSUDP fingerprints a UDP/53 DNS server with the same CHAOS TXT
// query set used by the TCP probe. If every response is truncated (TC=1),
// it falls back to TCP/53 — RFC 1035 §4.2.1 mandates this behaviour.
func probeDNSUDP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial DNS UDP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	answers, rcode, ra, err := dnsRunFingerprint(&dns.Conn{Conn: conn})
	if err == nil {
		return dnsBuildResult(target, productDNS, answers, rcode, ra), nil
	}

	if !errors.Is(err, errDNSTruncated) {
		return nil, err
	}

	tcpTarget := target
	tcpTarget.Transport = TransportTCP

	tcpConn, tcpErr := s.dialTCP(ctx, tcpTarget)
	if tcpErr != nil {
		return nil, fmt.Errorf("dns: UDP truncated and TCP fallback failed: %w", tcpErr)
	}

	defer func() { _ = tcpConn.Close() }()

	answers, rcode, ra, err = dnsRunFingerprint(&dns.Conn{Conn: tcpConn})
	if err != nil {
		return nil, err
	}

	return dnsBuildResult(target, productDNS, answers, rcode, ra), nil
}
