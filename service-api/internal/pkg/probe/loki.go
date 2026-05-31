package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const productGrafanaLoki = "grafana_loki"

func init() {
	// 3100 — Grafana Loki HTTP API (read & write paths share the port).
	Register(probeLoki, 3100)
}

// probeLoki fingerprints Grafana Loki via /loki/api/v1/status/buildinfo
// (added in Loki 2.0). Response shape mirrors Prometheus:
//
//	{"version":"2.9.4","revision":"...","branch":"...","buildUser":"...","goVersion":"..."}
//
// /ready ("ready\n") is used as a fallback when buildinfo is firewalled.
func probeLoki(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/loki/api/v1/status/buildinfo", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Loki request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/Loki")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Loki buildinfo: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	var info struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
		Branch   string `json:"branch"`
	}

	if jsonErr := json.Unmarshal(body, &info); jsonErr == nil && info.Version != "" {
		fp := &FingerprintResult{
			Product: productGrafanaLoki,
			Version: info.Version,
			Edition: info.Branch,
			RawJSON: body,
		}

		return &Result{
			Target:      target,
			Protocol:    productGrafanaLoki,
			Banner:      "Grafana Loki " + info.Version,
			Fingerprint: fp,
		}, nil
	}

	// /ready fallback — single token plain text.
	readyURL := fmt.Sprintf("http://%s/ready", addr)

	readyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, readyURL, nil)
	if err == nil {
		readyReq.Header.Set("User-Agent", "UltraViolet/Loki")

		if readyResp, readyErr := client.Do(readyReq); readyErr == nil {
			defer func() { _ = readyResp.Body.Close() }()

			readyBody, _ := io.ReadAll(io.LimitReader(readyResp.Body, 256))

			if strings.Contains(strings.ToLower(string(readyBody)), "ready") {
				return &Result{
					Target:   target,
					Protocol: productGrafanaLoki,
					Banner:   "Grafana Loki (ready)",
					Fingerprint: &FingerprintResult{
						Product: productGrafanaLoki,
						RawJSON: mustMarshalJSON(map[string]any{"ready": true}),
					},
				}, nil
			}
		}
	}

	return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
}
