package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const productLinkerdProxy = "linkerd_proxy"

// linkerdVersionRE matches Prometheus help comments that the Linkerd
// proxy embeds in its /metrics output, e.g.
//
//	# HELP linkerd_build_info Linkerd build metadata
//	linkerd_build_info{version="stable-2.14.7",...} 1
var linkerdVersionRE = regexp.MustCompile(`linkerd_build_info\{[^}]*version="([^"]+)"`)

func init() {
	// 4191 — Linkerd proxy admin / Prometheus scrape endpoint.
	Register(probeLinkerd, 4191)
}

// probeLinkerd fingerprints a Linkerd2 sidecar proxy via its admin
// /metrics endpoint. The proxy is one of the few sidecars that exposes
// its build version directly as a Prometheus gauge labels.
func probeLinkerd(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/metrics", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Linkerd request: %w", err)
	}

	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "UltraViolet/Linkerd")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Linkerd /metrics: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	raw := string(body)
	lower := strings.ToLower(raw)

	if !strings.Contains(lower, "linkerd") {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: raw}, nil
	}

	var version string

	if match := linkerdVersionRE.FindStringSubmatch(raw); len(match) == 2 {
		version = match[1]
	}

	fp := &FingerprintResult{
		Product: productLinkerdProxy,
		Version: version,
		RawJSON: mustMarshalJSON(map[string]any{
			"version":     version,
			"http_status": resp.StatusCode,
		}),
	}

	banner := "Linkerd proxy"
	if version != "" {
		banner = "Linkerd proxy " + version
	}

	return &Result{
		Target:      target,
		Protocol:    productLinkerdProxy,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}
