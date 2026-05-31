package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/miekg/dns"
)

const productDoT = "dns_over_tls"

func init() {
	// 853 — DNS over TLS (RFC 7858).
	Register(probeDoT, 853)
}

// probeDoT establishes a TLS session against the target, then runs the
// shared CHAOS TXT fingerprint pass to capture resolver branding. The TLS
// leaf is attached so downstream consumers can correlate by certificate.
func probeDoT(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}) //nolint:gosec // scanner probes self-signed certs

	if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
		return nil, fmt.Errorf("dot: TLS handshake failed: %w", hsErr)
	}

	defer func() { _ = tlsConn.Close() }()

	tlsResult := dotCaptureLeaf(tlsConn)

	answers, rcode, ra, err := dnsRunFingerprint(&dns.Conn{Conn: tlsConn})
	if err != nil {
		return nil, fmt.Errorf("dot: fingerprint failed: %w", err)
	}

	result := dnsBuildResult(target, productDoT, answers, rcode, ra)
	result.Protocol = productDoT
	result.TLS = tlsResult

	return result, nil
}

// dotCaptureLeaf packages the leaf cert into a TLSResult.
func dotCaptureLeaf(tlsConn *tls.Conn) *TLSResult {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	leaf := state.PeerCertificates[0]

	fingerprint := sha256.Sum256(leaf.Raw)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	return &TLSResult{
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		RawPEM:            string(pemBytes),
		SANs:              leaf.DNSNames,
		TLSVersion:        tls.VersionName(state.Version),
		CipherSuite:       tls.CipherSuiteName(state.CipherSuite),
	}
}
