package probe

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

const productCODESYS = "codesys_v3"

func init() {
	// CODESYS V3 Gateway Server (Communication Server). 1217 is the
	// historical default; ABB, Bosch Rexroth, Schneider M251 and Wago
	// PFC200 inherit it. 11740 = CODESYS V2 Gateway (less common in
	// modern installs). 1740-1743 = older CODESYS Programming Driver.
	Register(probeCODESYS, 1217, 11740)
}

// probeCODESYS detects a CODESYS V3 Gateway / Programming Driver. The
// wire protocol is proprietary, but every supported runtime shares a
// 4-byte block-driver "magic" (BB BB 00 BB) that the gateway sends in
// the first response packet of any tagged-block exchange.
//
// We don't reverse the full block-driver dialect — that's a 2000-line
// Wireshark dissector — we issue a single SERVICE_DISCOVERY frame and
// look for the magic. If TLS is configured (CODESYS Edge Gateway 4.x+
// or Schneider EcoStruxure Control Expert proxies), we fall back to a
// TLS handshake to confirm the protocol over the encrypted transport.
//
// Detection-only is intentional: vendor firmware revisions only show up
// after an authenticated session, which always requires a project
// password. Catalog CVEs on `codesys:codesys_runtime` are version-
// agnostic almost without exception, so a Product-only fingerprint
// still yields useful matches.
func probeCODESYS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	// The gateway either speaks plain block-driver (legacy) or TLS-on-top
	// (newer). Try the plain path first and only fall back to TLS if the
	// peer immediately returns an EOF — that's the unmistakable signature
	// of CODESYS V4 Edge Gateway expecting a ClientHello.
	if _, writeErr := conn.Write(codesysDiscoveryPacket); writeErr != nil {
		return nil, writeErr
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 256)

	n, err := conn.Read(buf)
	if err == nil && n >= 4 && isCODESYSMagic(buf[:n]) {
		return codesysResult(target, buf[:n], "plain"), nil
	}

	if (err == io.EOF || (err == nil && n == 0)) && tryCODESYSTLS(ctx, s, target) {
		return &Result{
			Target:   target,
			Protocol: productCODESYS,
			Banner:   "CODESYS V3 Edge Gateway (TLS)",
			Fingerprint: &FingerprintResult{
				Product:     productCODESYS,
				TLSRequired: boolPtr(true),
				RawJSON:     []byte(`{"transport":"tls"}`),
			},
		}, nil
	}

	if err != nil || n == 0 {
		return &Result{Target: target, Protocol: protocolTCP}, errors.New("codesys: no reply")
	}

	return &Result{Target: target, Protocol: protocolTCP, Banner: hex.EncodeToString(buf[:n])}, nil
}

// codesysDiscoveryPacket asks the V3 block driver to identify itself.
// The packet is 16 bytes wide:
//
//	BB BB 00 BB                — fixed block-driver magic (V3)
//	02 00 00 00                — service ID 2 (CmpGateway)
//	00 00 00 00                — channel ID = 0 (broadcast)
//	00 00 00 00                — payload length = 0
//
// V3 responds with the same magic in its header, V2 silently closes the
// connection.
var codesysDiscoveryPacket = []byte{
	0xBB, 0xBB, 0x00, 0xBB,
	0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

func isCODESYSMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0xBB && b[1] == 0xBB && b[2] == 0x00 && b[3] == 0xBB
}

func codesysResult(target Target, payload []byte, transport string) *Result {
	limit := len(payload)
	if limit > 64 {
		limit = 64
	}

	return &Result{
		Target:   target,
		Protocol: productCODESYS,
		Banner:   "CODESYS V3 Gateway",
		Fingerprint: &FingerprintResult{
			Product: productCODESYS,
			RawJSON: mustMarshalJSON(map[string]any{
				"transport":    transport,
				"reply_prefix": hex.EncodeToString(payload[:limit]),
				"reply_length": len(payload),
				"block_driver": "BB BB 00 BB",
			}),
		},
	}
}

// tryCODESYSTLS opens a fresh TCP connection and attempts a TLS
// handshake. CODESYS V4 Edge Gateway always responds to ClientHello
// regardless of mTLS settings, so a successful handshake is a strong
// positive signal even when peer auth is required.
func tryCODESYSTLS(ctx context.Context, s *Stack, target Target) bool {
	c2, err := s.dialTCP(ctx, target)
	if err != nil {
		return false
	}

	defer func() { _ = c2.Close() }()

	tlsConn := tls.Client(c2, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // CODESYS edge gateways universally use self-signed certs

	deadline := time.Now().Add(s.probeTimeout(ctx))

	_ = tlsConn.SetDeadline(deadline)

	return tlsConn.HandshakeContext(ctx) == nil
}
