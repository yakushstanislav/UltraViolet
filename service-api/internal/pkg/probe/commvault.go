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

const productCommvault = "commvault_backup"

func init() {
	// 8400 — Commvault Communication Server HTTPS management front-end
	// (Web Console / CommServe REST). Older 1996 has been deprecated.
	Register(probeCommvault, 8400)
}

// probeCommvault fingerprints Commvault Backup & Recovery deployments.
// `/SearchSvc/CVWebService.svc/ApplianceMeta` is the documented anonymous
// metadata endpoint that ships with every Web Console install and never
// requires authentication.
func probeCommvault(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("https://%s/SearchSvc/CVWebService.svc/ApplianceMeta", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Commvault request: %w", err)
	}

	req.Header.Set("Accept", "application/xml")
	req.Header.Set("User-Agent", "UltraViolet/Commvault")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Commvault metadata: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	raw := string(body)
	lower := strings.ToLower(raw + " " + resp.Header.Get("Server"))

	if !strings.Contains(lower, "commvault") &&
		!strings.Contains(lower, "appliancemeta") &&
		!strings.Contains(lower, "cvwebservice") {
		return &Result{Target: target, Protocol: protocolHTTPS, Banner: raw}, nil
	}

	version := extractXMLAttr(raw, "Version")
	servicePack := extractXMLAttr(raw, "SP")

	fp := &FingerprintResult{
		Product: productCommvault,
		Version: version,
		Edition: servicePack,
		RawJSON: mustMarshalJSON(map[string]any{
			"version":      version,
			"service_pack": servicePack,
			"http_status":  resp.StatusCode,
		}),
	}

	banner := "Commvault Backup & Recovery"
	if version != "" {
		banner = banner + " " + version
	}

	return &Result{
		Target:      target,
		Protocol:    productCommvault,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// extractXMLAttr pulls the first occurrence of attr="value" from the given
// XML / SOAP body. It is intentionally permissive — Commvault's payload
// shape varies across builds.
func extractXMLAttr(body, attr string) string {
	needle := attr + `="`

	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}

	rest := body[idx+len(needle):]

	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}

	return rest[:end]
}
