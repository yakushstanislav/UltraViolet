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

const productAlertmanager = "prometheus_alertmanager"

func init() {
	// 9093 — Prometheus Alertmanager UI / API.
	Register(probeAlertmanager, 9093)
}

// probeAlertmanager targets /api/v2/status, which is unauthenticated by
// default and returns a JSON envelope:
//
//	{
//	  "cluster":{...},
//	  "versionInfo":{"version":"0.27.0","revision":"...","branch":"..."},
//	  "uptime":"...",
//	  "config":{...}
//	}
func probeAlertmanager(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/api/v2/status", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Alertmanager request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/Alertmanager")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Alertmanager status: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	var info struct {
		VersionInfo struct {
			Version  string `json:"version"`
			Revision string `json:"revision"`
			Branch   string `json:"branch"`
			GoVer    string `json:"goVersion"`
		} `json:"versionInfo"`
	}

	if jsonErr := json.Unmarshal(body, &info); jsonErr != nil || info.VersionInfo.Version == "" {
		raw := strings.ToLower(string(body))

		if !strings.Contains(raw, "alertmanager") && !strings.Contains(raw, "versioninfo") {
			return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
		}

		return &Result{
			Target:   target,
			Protocol: productAlertmanager,
			Banner:   "Prometheus Alertmanager",
			Fingerprint: &FingerprintResult{
				Product: productAlertmanager,
				RawJSON: body,
			},
		}, nil
	}

	fp := &FingerprintResult{
		Product: productAlertmanager,
		Version: info.VersionInfo.Version,
		Edition: info.VersionInfo.Branch,
		RawJSON: body,
	}

	return &Result{
		Target:      target,
		Protocol:    productAlertmanager,
		Banner:      "Prometheus Alertmanager " + info.VersionInfo.Version,
		Fingerprint: fp,
	}, nil
}
