package probe

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const (
	productOTLP = "opentelemetry_collector"
	// otlpHTTPTracesPath is the canonical OTLP/HTTP traces endpoint.
	otlpHTTPTracesPath = "/v1/traces"
	// otlpGRPCExportMethod is the OTLP/gRPC TraceService.Export method
	// path. Even a malformed request produces a recognisable gRPC reply.
	otlpGRPCExportMethod = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
)

// otlpResponseLimit caps how many bytes we read from an OTLP response
// while sniffing for collector-style error envelopes.
const otlpResponseLimit = 4 * 1024

func init() {
	Register(probeOTLPHTTP, 4318)
	Register(probeOTLPGRPC, 4317)
}

// probeOTLPHTTP fingerprints an OTLP/HTTP receiver on TCP/4318. The
// detection POSTs an empty traces envelope and looks for OpenTelemetry
// collector signatures in the response.
func probeOTLPHTTP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := &http.Client{
		Transport: s.httpTransport,
		Timeout:   s.cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if detectOTLPHTTP(ctx, client, protocolHTTP, addr, s.cfg.UserAgent) {
		return &Result{
			Target:      target,
			Protocol:    productOTLP,
			Fingerprint: &FingerprintResult{Product: productOTLP, Edition: "http"},
		}, nil
	}

	return &Result{Target: target, Protocol: protocolTCP}, nil
}

// probeOTLPGRPC fingerprints an OTLP/gRPC receiver on TCP/4317. The probe
// uses the shared gRPC client (h2c, no TLS) and POSTs an empty frame to
// the TraceService.Export method — a real OTLP collector responds with a
// grpc-status header even when the payload is malformed.
func probeOTLPGRPC(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := newGRPCClient(s.cfg.Timeout, false)

	defer client.CloseIdleConnections()

	url := protocolHTTP + "://" + addr + otlpGRPCExportMethod

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(grpcEmptyFrame))
	if err != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Grpc-Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	defer func() { _ = resp.Body.Close() }()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, otlpResponseLimit))

	statusHeader := resp.Header.Get("Grpc-Status")
	statusTrailer := resp.Trailer.Get("Grpc-Status")

	if statusHeader == "" && statusTrailer == "" {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	return &Result{
		Target:      target,
		Protocol:    productOTLP,
		GRPC:        &GRPCResult{Detected: true},
		Fingerprint: &FingerprintResult{Product: productOTLP, Edition: "grpc"},
	}, nil
}

// detectOTLPHTTP POSTs an empty traces body and looks for collector-style
// hints in the response. Returns true when status or body indicate the
// peer is an OTLP/HTTP receiver.
func detectOTLPHTTP(ctx context.Context, client *http.Client, scheme, addr, userAgent string) bool {
	url := scheme + "://" + addr + otlpHTTPTracesPath

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(nil))
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	defer func() { _ = resp.Body.Close() }()

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "x-protobuf") || strings.Contains(contentType, "application/protobuf") {
		return true
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, otlpResponseLimit))
	if err != nil {
		return false
	}

	lowered := strings.ToLower(string(body))

	// Collector error envelopes typically mention one of these tokens.
	for _, marker := range []string{"otlp", "partial_success", "rejected_spans", "open-telemetry", "opentelemetry"} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}

	return false
}
