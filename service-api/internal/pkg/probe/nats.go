package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// productNATS matches the cpemap.productMap key so cvematch's Lookup hits.
// The on-the-wire product name is "nats-server", but the cpemap entry is
// keyed by the vendor-neutral "nats".
const productNATS = "nats"

func init() {
	Register(probeNATS, 4222)
}

// probeNATS captures the server-pushed INFO line that nats-server emits
// immediately on TCP accept. The payload is "INFO {json}\r\n" — see
// https://docs.nats.io/reference/reference-protocols/nats-protocol.
// We parse just enough to derive a Product/Version fingerprint and to flag
// whether the cluster requires auth or TLS for clients.
func probeNATS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial NATS: %w", err)
	}

	defer func() { _ = conn.Close() }()

	buf := make([]byte, 2048)

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("can't read NATS INFO: %w", err)
	}

	line := strings.TrimRight(string(buf[:n]), "\r\n")

	if !strings.HasPrefix(line, "INFO ") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: line}, nil
	}

	payload := strings.TrimPrefix(line, "INFO ")

	var info struct {
		ServerID     string `json:"server_id"`
		ServerName   string `json:"server_name"`
		Version      string `json:"version"`
		Go           string `json:"go"`
		Host         string `json:"host"`
		Proto        int    `json:"proto"`
		AuthRequired bool   `json:"auth_required"`
		TLSRequired  bool   `json:"tls_required"`
		Cluster      string `json:"cluster"`
	}

	if jsonErr := json.Unmarshal([]byte(payload), &info); jsonErr != nil {
		return &Result{Target: target, Protocol: productNATS, Banner: line}, nil
	}

	authRequired := info.AuthRequired
	tlsRequired := info.TLSRequired

	fp := &FingerprintResult{
		Product:      productNATS,
		Version:      info.Version,
		ClusterName:  info.Cluster,
		AuthRequired: &authRequired,
		TLSRequired:  &tlsRequired,
		RawJSON:      []byte(payload),
	}

	if info.Go != "" {
		fp.Edition = info.Go
	}

	if !authRequired && !tlsRequired {
		fp.Anonymous = true
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Banner:      line,
		Fingerprint: fp,
	}, nil
}
