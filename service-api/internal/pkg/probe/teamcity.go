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

const productTeamCity = "jetbrains_teamcity"

// teamcityVersionRE pulls out `version="2024.03 (build 147512)"` style
// attributes from the /app/rest/server response.
var teamcityVersionRE = regexp.MustCompile(`(?i)version="([^"]+)"`)

func init() {
	// 8111 — TeamCity server default HTTP. HTTPS gateways front it on
	// 8443 (covered by probeHTTPS) or 443.
	Register(probeTeamCity, 8111)
}

// probeTeamCity fingerprints a TeamCity server via /app/rest/server.
// Even when guest auth is disabled, /login.html and /favicon.ico still
// expose the X-TeamCity-* headers. We try the REST endpoint first and
// fall back to the Server / X-TeamCity-Node-Id headers if it is gated.
func probeTeamCity(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	for _, path := range []string{"/app/rest/server", "/"} {
		url := fmt.Sprintf("http://%s%s", addr, path)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("can't build TeamCity request: %w", err)
		}

		req.Header.Set("Accept", "application/xml,text/html")
		req.Header.Set("User-Agent", "UltraViolet/TeamCity")

		resp, doErr := client.Do(req)
		if doErr != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

		_ = resp.Body.Close()

		raw := string(body)
		hdrLower := strings.ToLower(resp.Header.Get("Server"))
		nodeID := resp.Header.Get("X-TeamCity-Node-Id")

		if !strings.Contains(strings.ToLower(raw), "teamcity") &&
			!strings.Contains(hdrLower, "teamcity") &&
			nodeID == "" {
			continue
		}

		var version string

		if match := teamcityVersionRE.FindStringSubmatch(raw); len(match) == 2 {
			version = match[1]
		}

		fp := &FingerprintResult{
			Product: productTeamCity,
			Version: version,
			Edition: nodeID,
			RawJSON: mustMarshalJSON(map[string]any{
				"endpoint":      path,
				"http_status":   resp.StatusCode,
				"server":        resp.Header.Get("Server"),
				"teamcity_node": nodeID,
				"version":       version,
			}),
		}

		banner := "TeamCity"
		if version != "" {
			banner = banner + " " + version
		}

		return &Result{
			Target:      target,
			Protocol:    productTeamCity,
			Banner:      banner,
			Fingerprint: fp,
		}, nil
	}

	return &Result{Target: target, Protocol: protocolHTTP}, nil
}
