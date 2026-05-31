package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

const productBareos = "bareos"

func init() {
	// 9101 — Bareos Director
	// 9102 — Bareos File Daemon (FD)
	// 9103 — Bareos Storage Daemon (SD)
	// All three speak the same handshake style (PAM-TLS / NDMP-ish): a
	// "Hello" line over plaintext, then an optional TLS upgrade. We try
	// a TLS handshake directly — Bareos servers configured with the
	// default `TLS Enable = yes` answer.
	Register(probeBareos, 9101, 9102, 9103)
}

// probeBareos performs a TLS handshake against a Bareos daemon and inspects
// the certificate Subject for the "Bareos" / "Bacula" markers Bareos
// installers default to. When TLS is disabled, the daemon emits a short
// ASCII "Hello" banner instead — we fall back to a plaintext read.
func probeBareos(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // scanner probes self-signed Bareos certs
	if hsErr := tlsConn.HandshakeContext(ctx); hsErr == nil {
		res, resErr := bareosFromTLS(target, tlsConn)
		_ = tlsConn.Close()

		return res, resErr
	}

	_ = tlsConn.Close()

	// Plaintext fallback — the first socket may be half-consumed after a
	// failed TLS handshake, so open a fresh connection for the banner read.
	conn2, dialErr := s.dialTCP(ctx, target)
	if dialErr != nil {
		return nil, dialErr
	}

	defer func() { _ = conn2.Close() }()

	buf := make([]byte, 512)

	n, _ := conn2.Read(buf)

	banner := strings.TrimRight(string(buf[:n]), "\r\n\x00")

	if !strings.Contains(strings.ToLower(banner), "bareos") &&
		!strings.Contains(strings.ToLower(banner), "bacula") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: banner}, nil
	}

	fp := &FingerprintResult{
		Product: productBareos,
		RawJSON: mustMarshalJSON(map[string]any{"banner": banner}),
	}

	return &Result{
		Target:      target,
		Protocol:    productBareos,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// bareosFromTLS inspects the leaf cert for a Bareos-issued Subject and
// produces a fingerprint when matched.
func bareosFromTLS(target Target, tlsConn *tls.Conn) (*Result, error) {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("bareos: TLS handshake returned no certs")
	}

	leaf := state.PeerCertificates[0]

	fingerprint := sha256.Sum256(leaf.Raw)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	tlsResult := &TLSResult{
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

	subjLower := strings.ToLower(leaf.Subject.String() + " " + leaf.Issuer.String())

	if !strings.Contains(subjLower, "bareos") && !strings.Contains(subjLower, "bacula") {
		return &Result{
			Target:   target,
			Protocol: protocolTCP,
			TLS:      tlsResult,
		}, nil
	}

	fp := &FingerprintResult{
		Product: productBareos,
		RawJSON: mustMarshalJSON(map[string]any{
			"subject": leaf.Subject.String(),
			"issuer":  leaf.Issuer.String(),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productBareos,
		Banner:      leaf.Subject.String(),
		TLS:         tlsResult,
		Fingerprint: fp,
	}, nil
}
