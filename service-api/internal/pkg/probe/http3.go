package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const protocolHTTP3 = "http3"

func init() {
	RegisterUDP(probeHTTP3, 443)
}

// probeHTTP3 dials the target over QUIC, performs an HTTP/3 GET / and
// packages the response plus the negotiated TLS state into a Result. The
// QUIC connection is captured via the http3.Transport Dial hook so we can
// extract the leaf certificate after the request completes.
func probeHTTP3(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	var capturedConn *quic.Conn

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanner probes arbitrary hosts
		NextProtos:         []string{"h3"},
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			conn, err := quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}

			capturedConn = conn

			return conn, nil
		},
	}

	defer func() { _ = transport.Close() }()

	client := &http.Client{Transport: transport, Timeout: s.cfg.Timeout}

	url := "https://" + addr + "/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build HTTP/3 request: %w", err)
	}

	req.Header.Set("User-Agent", s.cfg.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't perform HTTP/3 request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	if err != nil {
		return nil, fmt.Errorf("can't read HTTP/3 body: %w", err)
	}

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	httpResult := &HTTPResult{
		StatusCode:     resp.StatusCode,
		Server:         resp.Header.Get("Server"),
		Title:          extractTitle(body),
		Headers:        headers,
		Body:           string(body),
		Technologies:   detectTechnologies(headers, string(body)),
		AltSvcRaw:      resp.Header.Get("Alt-Svc"),
		HTTP3Supported: true,
	}

	result := &Result{
		Target:   target,
		Protocol: protocolHTTP3,
		HTTP:     httpResult,
	}

	if capturedConn != nil {
		state := capturedConn.ConnectionState().TLS
		result.TLS = tlsFromQUICState(state)

		if result.TLS != nil {
			analyzeTLS(target, &state, result.TLS)
		}
	}

	if fp := fingerprintFromHTTP(httpResult); fp != nil {
		result.Protocol = fp.Product
		result.Fingerprint = fp
	}

	result.Components = collectHTTPComponents(httpResult, result.Fingerprint)

	return result, nil
}

// tlsFromQUICState reduces a tls.ConnectionState (as exposed by quic-go)
// to the probe's TLSResult shape, reusing the existing certificate helpers
// so the persisted schema is identical between HTTPS/1.1 and HTTP/3.
func tlsFromQUICState(state tls.ConnectionState) *TLSResult {
	if len(state.PeerCertificates) == 0 {
		return nil
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

	return result
}
