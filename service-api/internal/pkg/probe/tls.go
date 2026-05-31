package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	jarm "github.com/hdm/jarm-go"
	"golang.org/x/sync/errgroup"
)

func init() {
	// 443 / 4443 / 8443 / 9443 / 10443 — canonical HTTPS and common admin alts.
	// 992   — telnets (telnet wrapped in TLS, RFC 2595); TLS handshake alone
	//         yields a useful cert + JARM even though our HTTP GET will fail.
	// 8444  — HTTPS alt used by tomcat/jboss console deployments.
	// 10000 — Webmin / Usermin admin console (HTTPS-by-default).
	// 55443 — Cisco WLC / Aironet WebAuth admin HTTPS.
	// 6443  — Kubernetes API server
	// 10250 — kubelet HTTPS
	// 2380  — etcd peer TLS
	// 8883  — MQTT over TLS
	// 7443  — common ingress / admin HTTPS alt
	Register(probeHTTPS, 443, 992, 4443, 7443, 8443, 8444, 8883, 9443, 10000, 10250, 10443, 2380, 6443, 55443)
}

// probeHTTPS performs a TLS handshake, captures the leaf certificate, and
// then runs an HTTPS GET to enrich with HTTP-level metadata. The HTTP step
// is best-effort: TLS-only results still ship a meaningful Result.
func probeHTTPS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	tlsResult, err := s.handshakeTLS(ctx, target)
	if err != nil {
		return nil, err
	}

	return s.probeHTTPSWithTLS(ctx, target, tlsResult), nil
}

// probeHTTPSWithTLS continues an HTTPS probe from an already-captured TLS
// result. The banner fallback uses this to avoid the wasted handshake of
// calling probeHTTPS again after it has already completed one to detect a
// silent TLS server.
func (s *Stack) probeHTTPSWithTLS(ctx context.Context, target Target, tlsResult *TLSResult) *Result {
	if s.cfg.JARMEnabled {
		s.probeJARM(ctx, target, tlsResult)
	}

	result := &Result{
		Target:   target,
		Protocol: protocolHTTPS,
		TLS:      tlsResult,
	}

	if httpResult, httpErr := s.httpRequest(ctx, target, true); httpErr == nil && httpResult != nil {
		result.HTTP = httpResult.HTTP

		if httpResult.Fingerprint != nil {
			result.Protocol = httpResult.Protocol
			result.Fingerprint = httpResult.Fingerprint
		}
	}

	// TLS-only fallback: many admin panels disable HTTP banners on
	// purpose but still ship a distinctive self-signed cert (e.g.
	// "Kubernetes Ingress Controller Fake Certificate"). When the
	// HTTPS GET above didn't produce a fingerprint, fall back to TLS
	// subject hints. Version stays empty — cvematch handles version-
	// less applicability through the cpemap product map.
	if result.Fingerprint == nil {
		if fp := tlsSubjectHint(tlsResult); fp != nil {
			result.Protocol = fp.Product
			result.Fingerprint = fp
		}
	}

	// Inline gRPC sniff: TLS-fronted gRPC servers are indistinguishable
	// from regular HTTPS on the wire until you POST application/grpc, so
	// every h2-capable peer gets one cheap reflection request.
	if tlsResult.NegotiatedProtocol == "h2" {
		if gr := s.detectGRPCOverHTTPS(ctx, target); gr != nil && gr.Detected {
			result.GRPC = gr

			if result.Fingerprint == nil {
				result.Protocol = productGRPC
				result.Fingerprint = &FingerprintResult{Product: productGRPC}
			}
		}
	}

	return result
}

// handshakeTLS opens a TLS connection, captures the leaf cert, and closes
// the connection. It does not perform any HTTP traffic.
func (s *Stack) handshakeTLS(ctx context.Context, target Target) (*TLSResult, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	netDialer := &net.Dialer{Timeout: s.cfg.Timeout}

	conn, err := (&tls.Dialer{
		NetDialer: netDialer,
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // scanner probes arbitrary hosts
			// Offer both ALPN protocols so peers reveal h2 support (e.g. gRPC
			// servers on 443/8443). The follow-up HTTPS GET runs on a separate
			// connection and will renegotiate as it likes.
			NextProtos: []string{"h2", "http/1.1"},
		},
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("can't complete TLS handshake: %w", err)
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()

		return nil, errors.New("TLS dial returned non-TLS connection")
	}

	_ = tlsConn.SetDeadline(deadlineFromCtx(ctx, s.cfg.Timeout))

	defer func() { _ = tlsConn.Close() }()

	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("TLS handshake returned no certificates")
	}

	result := leafCertToResult(state.PeerCertificates[0])
	result.TLSVersion = tls.VersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.NegotiatedProtocol = state.NegotiatedProtocol

	if len(state.PeerCertificates) > 1 {
		chain := make([]TLSCertificate, 0, len(state.PeerCertificates)-1)
		for _, cert := range state.PeerCertificates[1:] {
			chain = append(chain, certToChainNode(cert))
		}

		result.Chain = chain
	}

	result.JA3SHash = serverHelloJA3S(state)
	result.JA4SHash = serverHelloJA4S(state)

	analyzeTLS(target, &state, result)

	return result, nil
}

// leafCertToResult packages an x509 leaf certificate into a TLSResult,
// including a SHA-256 fingerprint, PEM-encoded copy, and SANs.
func leafCertToResult(leaf *x509.Certificate) *TLSResult {
	fingerprint := sha256.Sum256(leaf.Raw)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leaf.Raw,
	})

	return &TLSResult{
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		RawPEM:            string(pemBytes),
		SANs:              leaf.DNSNames,
	}
}

// certToChainNode reduces an x509 certificate to the persisted node shape.
func certToChainNode(cert *x509.Certificate) TLSCertificate {
	fingerprint := sha256.Sum256(cert.Raw)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return TLSCertificate{
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		RawPEM:            string(pemBytes),
		SANs:              cert.DNSNames,
	}
}

// serverHelloJA3S builds a lightweight JA3S-like fingerprint string from the
// negotiated TLS version + cipher suite. (Go stdlib does not expose the raw
// ServerHello extension list, so this is a stable approximation rather than
// the canonical JA3S.)
func serverHelloJA3S(state tls.ConnectionState) string {
	payload := []byte(strconv.Itoa(int(state.Version)) + "," + strconv.Itoa(int(state.CipherSuite)))

	if state.NegotiatedProtocol != "" {
		payload = append(payload, ',')
		payload = append(payload, state.NegotiatedProtocol...)
	}

	sum := sha256.Sum256(payload)

	return "ja3s-stub_" + hex.EncodeToString(sum[:8])
}

// serverHelloJA4S is the JA4S-style summary "tNNcCC<alpn>": t13c1301h2.
func serverHelloJA4S(state tls.ConnectionState) string {
	version := "?"

	switch state.Version {
	case tls.VersionTLS10:
		version = "10"
	case tls.VersionTLS11:
		version = "11"
	case tls.VersionTLS12:
		version = "12"
	case tls.VersionTLS13:
		version = "13"
	}

	alpn := state.NegotiatedProtocol
	if alpn == "" {
		alpn = "00"
	}

	return "t" + version + "c" + strconv.FormatUint(uint64(state.CipherSuite), 16) + alpn
}

// jarmParallelism caps simultaneous JARM probe dials per target. The full
// JARM suite is 10 handshakes; running them all at once would burst-load the
// peer and tends to trip rate-limiters, but a small pool still cuts wall time
// roughly fivefold vs. the serial loop.
const jarmParallelism = 5

// probeJARM sends 10 crafted TLS Client Hello packets and writes the resulting
// JARM fingerprint into tlsResult. Probes run in parallel under a bounded
// errgroup; results are collected by index because the final hash is
// order-sensitive. Per-probe errors are silently skipped — JARM is
// best-effort enrichment that must not fail the overall probe.
func (s *Stack) probeJARM(ctx context.Context, target Target, tlsResult *TLSResult) {
	host := target.IP.String()
	port := int(target.Port)
	probes := jarm.GetProbes(host, port)

	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	results := make([]string, len(probes))
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(jarmParallelism)

	for i, probe := range probes {
		group.Go(func() error {
			results[i] = jarmOneProbe(groupCtx, dialer, addr, timeout, probe)

			return nil
		})
	}

	_ = group.Wait()

	fp := jarm.RawHashToFuzzyHash(strings.Join(results, ","))
	if fp != jarm.ZeroHash {
		tlsResult.JARMFingerprint = fp
	}
}

// jarmOneProbe runs a single JARM handshake and returns the parsed server
// hello string, or "" on any failure (rate-limit, RST, malformed reply).
func jarmOneProbe(ctx context.Context, dialer *net.Dialer, addr string, timeout time.Duration, probe jarm.JarmProbeOptions) string {
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, writeErr := conn.Write(jarm.BuildProbe(probe)); writeErr != nil {
		return ""
	}

	buf := make([]byte, 1484)

	n, readErr := conn.Read(buf)
	if readErr != nil || n == 0 {
		return ""
	}

	parsed, parseErr := jarm.ParseServerHello(buf[:n], probe)
	if parseErr != nil {
		return ""
	}

	return parsed
}
