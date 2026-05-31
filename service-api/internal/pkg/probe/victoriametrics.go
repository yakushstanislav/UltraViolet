package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const productVictoriaMetrics = "victoria_metrics"

var vmVersionRE = regexp.MustCompile(`(?i)vmsingle|vmstorage|vmselect|vminsert`)

func init() {
	// 8428 — VictoriaMetrics single-node / vmselect HTTP API.
	Register(probeVictoriaMetrics, 8428)
}

// probeVictoriaMetrics targets the Prometheus-compatible status endpoints
// VictoriaMetrics exposes: /api/v1/status/buildinfo plus the lightweight
// /metrics page which advertises the binary name (vmsingle / vmselect /
// vmstorage / vminsert) as a Prometheus comment.
func probeVictoriaMetrics(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	buildinfoURL := fmt.Sprintf("http://%s/api/v1/status/buildinfo", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buildinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build VM request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/VictoriaMetrics")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch VictoriaMetrics buildinfo: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	var envelope struct {
		Data struct {
			Version  string `json:"version"`
			Revision string `json:"revision"`
			Branch   string `json:"branch"`
		} `json:"data"`
		Status string `json:"status"`
	}

	var (
		version  string
		revision string
	)

	if jsonErr := json.Unmarshal(body, &envelope); jsonErr == nil {
		version = envelope.Data.Version
		revision = envelope.Data.Revision
	}

	bodyLower := strings.ToLower(string(body))
	if version == "" && !vmVersionRE.MatchString(bodyLower) && !strings.Contains(bodyLower, "victoriametrics") {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
	}

	fp := &FingerprintResult{
		Product: productVictoriaMetrics,
		Version: version,
		Edition: revision,
		RawJSON: body,
	}

	banner := "VictoriaMetrics"
	if version != "" {
		banner = banner + " " + version
	}

	return &Result{
		Target:      target,
		Protocol:    productVictoriaMetrics,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}
