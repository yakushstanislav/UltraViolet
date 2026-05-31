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

const productCiliumAgent = "cilium_agent"

func init() {
	// 9963 — Cilium operator health check HTTP. The agent in-pod
	// listens on 9879 (already a different worker's territory only by
	// accident, but we still pick 9963 only).
	Register(probeCilium, 9963)
}

// probeCilium fingerprints a Cilium operator via the unauthenticated
// /healthz endpoint. The response is plain text "ok" plus the operator
// reveals itself through the Server header and the `Cilium` prefix on
// the response body of /version (added in 1.13+).
func probeCilium(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	for _, path := range []string{"/healthz", "/version", "/metrics"} {
		url := fmt.Sprintf("http://%s%s", addr, path)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "UltraViolet/Cilium")

		resp, doErr := client.Do(req)
		if doErr != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

		_ = resp.Body.Close()

		raw := strings.ToLower(string(body) + " " + resp.Header.Get("Server"))

		if !strings.Contains(raw, "cilium") {
			continue
		}

		return &Result{
			Target:   target,
			Protocol: productCiliumAgent,
			Banner:   "Cilium",
			Fingerprint: &FingerprintResult{
				Product: productCiliumAgent,
				RawJSON: mustMarshalJSON(map[string]any{
					"endpoint":    path,
					"http_status": resp.StatusCode,
					"snippet":     string(body),
				}),
			},
		}, nil
	}

	return &Result{Target: target, Protocol: protocolHTTP}, nil
}
