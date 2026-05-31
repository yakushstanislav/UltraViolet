package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const productGrafanaTempo = "grafana_tempo"

func init() {
	// 3200 — Grafana Tempo distributor / query frontend HTTP API.
	Register(probeTempo, 3200)
}

// probeTempo fingerprints Grafana Tempo using the unauthenticated
// /api/echo + /api/status endpoints. Newer Tempo builds (>=2.0) also
// expose /api/version returning plain text "version=...".
func probeTempo(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	versionURL := fmt.Sprintf("http://%s/api/echo", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Tempo request: %w", err)
	}

	req.Header.Set("User-Agent", "UltraViolet/Tempo")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Tempo /api/echo: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	raw := strings.ToLower(string(body) + " " + resp.Header.Get("Server"))

	if !strings.Contains(raw, "tempo") && !strings.Contains(raw, "echo") {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
	}

	return &Result{
		Target:   target,
		Protocol: productGrafanaTempo,
		Banner:   "Grafana Tempo",
		Fingerprint: &FingerprintResult{
			Product: productGrafanaTempo,
			RawJSON: mustMarshalJSON(map[string]any{
				"http_status": resp.StatusCode,
				"snippet":     string(body),
			}),
		},
	}, nil
}
