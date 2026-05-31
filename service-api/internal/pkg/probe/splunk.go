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

const productSplunk = "splunk"

// splunkVersionRE pulls out the embedded `<s:key name="version">9.1.4</s:key>`
// fragment from a Splunkd Atom/XML feed.
var splunkVersionRE = regexp.MustCompile(`(?i)<s:key\s+name="version">([^<]+)</s:key>`)

func init() {
	// 8089 — Splunkd management API (HTTPS, TLS-only, optional auth on
	// /services/server/info). Port 8000 (Splunk Web) collides with the
	// generic probeHTTP registration, so we route it via derived.go.
	Register(probeSplunk, 8089)
}

// probeSplunk fingerprints Splunk Enterprise / Splunk Cloud Forwarders by
// fetching the splunkd /services/server/info endpoint. The reply is an
// Atom-style XML document carrying the version, build, GUID and OS info.
func probeSplunk(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("https://%s/services/server/info", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Splunk request: %w", err)
	}

	req.Header.Set("Accept", "application/xml")
	req.Header.Set("User-Agent", "UltraViolet/Splunk")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Splunk server info: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	raw := string(body)

	serverHdr := resp.Header.Get("Server")
	lower := strings.ToLower(serverHdr + " " + raw)

	if !strings.Contains(lower, "splunk") && !strings.Contains(lower, "splunkd") {
		return &Result{Target: target, Protocol: protocolHTTPS, Banner: serverHdr}, nil
	}

	var version string

	if match := splunkVersionRE.FindStringSubmatch(raw); len(match) == 2 {
		version = match[1]
	}

	fp := &FingerprintResult{
		Product: productSplunk,
		Version: version,
		RawJSON: mustMarshalJSON(map[string]any{
			"server":      serverHdr,
			"http_status": resp.StatusCode,
			"version":     version,
		}),
	}

	banner := "Splunk"
	if version != "" {
		banner = "Splunk " + version
	}

	return &Result{
		Target:      target,
		Protocol:    productSplunk,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}
