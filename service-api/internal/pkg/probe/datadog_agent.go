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

const productDatadogAgent = "datadog_agent"

func init() {
	// 8126 — Datadog APM trace agent HTTP receiver. Anonymous GET /info
	// returns rich JSON metadata. UDP 8125 (statsd) is fire-and-forget,
	// so we keep this probe TCP-only.
	Register(probeDatadogAgent, 8126)
}

// probeDatadogAgent fingerprints the Datadog Agent trace receiver.
// /info reply (since trace-agent 7.41):
//
//	{
//	  "version":"7.50.0",
//	  "git_commit":"...",
//	  "endpoints":["/v0.3/traces", ...],
//	  "config":{...}
//	}
func probeDatadogAgent(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/info", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Datadog agent request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/DatadogAgent")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Datadog agent /info: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	var info struct {
		Version   string   `json:"version"`
		GitCommit string   `json:"git_commit"`
		Endpoints []string `json:"endpoints"`
	}

	if jsonErr := json.Unmarshal(body, &info); jsonErr != nil || info.Version == "" {
		raw := string(body)

		if !strings.Contains(strings.ToLower(raw), "trace-agent") &&
			!strings.Contains(strings.ToLower(raw), "datadog") {
			return &Result{Target: target, Protocol: protocolHTTP, Banner: raw}, nil
		}

		return &Result{
			Target:   target,
			Protocol: productDatadogAgent,
			Banner:   raw,
			Fingerprint: &FingerprintResult{
				Product: productDatadogAgent,
				RawJSON: mustMarshalJSON(map[string]any{
					"http_status": resp.StatusCode,
				}),
			},
		}, nil
	}

	fp := &FingerprintResult{
		Product: productDatadogAgent,
		Version: info.Version,
		Edition: info.GitCommit,
		RawJSON: body,
	}

	return &Result{
		Target:      target,
		Protocol:    productDatadogAgent,
		Banner:      "Datadog Agent " + info.Version,
		Fingerprint: fp,
	}, nil
}
