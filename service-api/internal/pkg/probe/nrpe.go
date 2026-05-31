package probe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"time"
)

const productNRPE = "nrpe"

func init() {
	// 5666 — Nagios NRPE (also used by check_mk agent and Centreon). NRPE 3+
	// requires TLS, but ciphers are limited to ADH-* by default so a normal
	// TLS dial often fails — we have to opt in to anonymous ciphers manually.
	Register(probeNRPE, 5666)
}

// probeNRPE first attempts the legacy v2 plaintext handshake: send a
// well-formed v2 packet asking for "_NRPE_CHECK" and read the response.
// Modern installs reject plaintext and close the connection; in that case
// fall back to a TLS dial with anonymous Diffie-Hellman enabled (the
// default for nrpe-3.x / nrpe-4.x). Either positive outcome proves NRPE.
func probeNRPE(ctx context.Context, s *Stack, target Target) (*Result, error) {
	if rawResult, ok := nrpeProbePlain(ctx, s, target); ok {
		return rawResult, nil
	}

	if tlsResult, ok := nrpeProbeTLS(ctx, s, target); ok {
		return tlsResult, nil
	}

	return nil, errors.New("nrpe: no response on plain or TLS")
}

func nrpeProbePlain(ctx context.Context, s *Stack, target Target) (*Result, bool) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, false
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	if _, writeErr := conn.Write(nrpeV2QueryPacket("_NRPE_CHECK")); writeErr != nil {
		return nil, false
	}

	buf := make([]byte, 1036) // v2 response packet size
	n, _ := io.ReadFull(conn, buf)

	if n < 4 {
		return nil, false
	}

	version := binary.BigEndian.Uint16(buf[:2])
	pktType := binary.BigEndian.Uint16(buf[2:4])

	if version != 2 || pktType != 2 { // 2=response
		return nil, false
	}

	bannerEnd := 10 + 1024
	if bannerEnd > n {
		bannerEnd = n
	}

	banner := strings.TrimRight(string(buf[10:bannerEnd]), "\x00\r\n ")

	return &Result{
		Target:   target,
		Protocol: productNRPE,
		Banner:   "NRPEv2 " + banner,
		Fingerprint: &FingerprintResult{
			Product: productNRPE,
			Version: nrpeBannerVersion(banner, "2"),
			RawJSON: mustMarshalJSON(map[string]any{
				"transport": "plain",
				"v2_reply":  banner,
			}),
		},
	}, true
}

func nrpeProbeTLS(ctx context.Context, s *Stack, target Target) (*Result, bool) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, false
	}

	defer func() { _ = conn.Close() }()

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // NRPE uses ADH; we never verify peer.
		// Anonymous ciphers are stripped from Go's stdlib TLS, so we can't
		// negotiate full ADH; an InsecureSkipVerify dial still succeeds
		// against modern NRPE when the daemon is built with --enable-ssl
		// and presents a self-signed RSA cert (most distro packages).
		MinVersion: tls.VersionTLS12,
	}

	tlsConn := tls.Client(conn, cfg)

	_ = tlsConn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
		return nil, false
	}

	tlsResult := dotCaptureLeaf(tlsConn)

	if _, writeErr := tlsConn.Write(nrpeV2QueryPacket("_NRPE_CHECK")); writeErr != nil {
		return nrpeTLSOnlyResult(target, tlsResult), true
	}

	buf := make([]byte, 1036)
	n, _ := io.ReadFull(tlsConn, buf)

	if n < 4 {
		return nrpeTLSOnlyResult(target, tlsResult), true
	}

	bannerEnd := 10 + 1024
	if bannerEnd > n {
		bannerEnd = n
	}

	banner := strings.TrimRight(string(buf[10:bannerEnd]), "\x00\r\n ")

	return &Result{
		Target:   target,
		Protocol: productNRPE,
		Banner:   "NRPE/TLS " + banner,
		TLS:      tlsResult,
		Fingerprint: &FingerprintResult{
			Product:     productNRPE,
			Version:     nrpeBannerVersion(banner, "3"),
			TLSRequired: boolPtr(true),
			RawJSON: mustMarshalJSON(map[string]any{
				"transport": "tls",
				"v2_reply":  banner,
			}),
		},
	}, true
}

func nrpeTLSOnlyResult(target Target, tlsResult *TLSResult) *Result {
	return &Result{
		Target:   target,
		Protocol: productNRPE,
		Banner:   "NRPE/TLS",
		TLS:      tlsResult,
		Fingerprint: &FingerprintResult{
			Product:     productNRPE,
			TLSRequired: boolPtr(true),
			RawJSON:     mustMarshalJSON(map[string]any{"transport": "tls"}),
		},
	}
}

// nrpeV2QueryPacket builds the legacy v2 query packet (1036 bytes).
//
//	uint16  packet_version  (BE, 2)
//	uint16  packet_type     (BE, 1 = query)
//	uint32  crc32           (left as zero; many daemons accept it)
//	uint16  result_code
//	char    buffer[1024]    (null-terminated command)
//	uint16  padding
func nrpeV2QueryPacket(command string) []byte {
	const packetSize = 1036

	pkt := make([]byte, packetSize)
	binary.BigEndian.PutUint16(pkt[0:2], 2) // version
	binary.BigEndian.PutUint16(pkt[2:4], 1) // query

	maxCmd := 1024 - 1
	if len(command) > maxCmd {
		command = command[:maxCmd]
	}

	copy(pkt[10:10+len(command)], command)

	return pkt
}

// nrpeBannerVersion pulls a "NRPE v2.15" / "version 4.0.3" style version out
// of the response payload. fallbackMajor is returned when the banner is
// silent (modern check_nrpe daemons reply with just "I (...)" or empty).
func nrpeBannerVersion(banner, fallbackMajor string) string {
	low := strings.ToLower(banner)

	if idx := strings.Index(low, "nrpe v"); idx >= 0 {
		return strings.TrimSpace(banner[idx+len("nrpe v"):])
	}

	if idx := strings.Index(low, "version "); idx >= 0 {
		return strings.TrimSpace(banner[idx+len("version "):])
	}

	return fallbackMajor
}
