package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const (
	productGRPC = "grpc"
	// grpcReflectionPath targets ServerReflection.ServerReflectionInfo —
	// every reflection-enabled gRPC server exposes this method.
	grpcReflectionPath = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
)

// grpcEmptyFrame is the smallest valid gRPC message frame: 1-byte
// compression flag + 4-byte BigEndian length + zero-length payload. A
// well-formed gRPC server replies with grpc-status on this even though
// the payload is not a real reflection request.
var grpcEmptyFrame = []byte{0, 0, 0, 0, 0}

func init() {
	Register(probeGRPC, 50051)
}

// probeGRPC fingerprints a plain-text h2c gRPC service on TCP/50051. The
// canonical use case is internal microservices that expose ServerReflection
// without TLS.
func probeGRPC(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := newGRPCClient(s.cfg.Timeout, false)

	defer client.CloseIdleConnections()

	gr, ok := probeGRPCEndpoint(ctx, client, protocolHTTP, addr, s.cfg.UserAgent)
	if !ok {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	return &Result{
		Target:      target,
		Protocol:    productGRPC,
		GRPC:        gr,
		Fingerprint: &FingerprintResult{Product: productGRPC},
	}, nil
}

// detectGRPCOverHTTPS issues a single gRPC reflection request over h2/TLS
// against the same target the HTTPS probe just completed. Called inline
// from probeHTTPSWithTLS when the TLS handshake negotiated h2.
func (s *Stack) detectGRPCOverHTTPS(ctx context.Context, target Target) *GRPCResult {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := newGRPCClient(s.cfg.Timeout, true)

	defer client.CloseIdleConnections()

	gr, _ := probeGRPCEndpoint(ctx, client, protocolHTTPS, addr, s.cfg.UserAgent)

	return gr
}

// probeGRPCEndpoint sends one gRPC request to the reflection path and
// inspects the response for gRPC framing markers. Returns (result, true)
// when the peer behaves like a gRPC server, (nil, false) otherwise.
func probeGRPCEndpoint(ctx context.Context, client *http.Client, scheme, addr, userAgent string) (*GRPCResult, bool) {
	url := scheme + "://" + addr + grpcReflectionPath

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(grpcEmptyFrame))
	if err != nil {
		return nil, false
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Grpc-Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}

	defer func() { _ = resp.Body.Close() }()

	// Drain the body so trailers populate.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	statusHeader := resp.Header.Get("Grpc-Status")
	statusTrailer := resp.Trailer.Get("Grpc-Status")
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))

	if statusHeader == "" && statusTrailer == "" && !strings.HasPrefix(contentType, "application/grpc") {
		return nil, false
	}

	gr := &GRPCResult{Detected: true}

	status := statusHeader
	if status == "" {
		status = statusTrailer
	}

	// 0 = OK, 12 = UNIMPLEMENTED. Anything but 12 means the server actually
	// processed the reflection method, i.e. reflection is exposed.
	if status != "" && status != "12" {
		gr.Reflection = true
	}

	return gr, true
}

// newGRPCClient builds an http.Client speaking HTTP/2 either as h2c (no
// TLS) or h2 over TLS. The TLS variant skips verification, matching the
// rest of the probe package.
func newGRPCClient(timeout time.Duration, useTLS bool) *http.Client {
	if !useTLS {
		transport := &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: timeout}

				return dialer.DialContext(ctx, network, addr)
			},
		}

		return &http.Client{Transport: transport, Timeout: timeout}
	}

	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // scanner probes arbitrary hosts
			NextProtos:         []string{"h2"},
		},
	}

	return &http.Client{Transport: transport, Timeout: timeout}
}
