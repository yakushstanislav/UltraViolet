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

const productVeeamBackup = "veeam_backup"

func init() {
	// 9419 — Veeam B&R REST API (HTTPS, JSON).
	// 9392 — Veeam B&R PSExec / management binary endpoint that emits
	//        a short TCP banner with the product name on connect.
	Register(probeVeeam, 9392, 9419)
}

// probeVeeam fingerprints Veeam Backup & Replication / Veeam Backup for
// Office 365 deployments. The two ports speak two different things:
//
//   - 9419 → HTTPS REST API. GET /api/v1/serverInfo (no auth on the
//     route) returns {"name":"...","buildVersion":"12.1.2.172",...}.
//   - 9392 → bespoke TCP banner that always carries "Veeam" / "VB&R"
//     in its preamble; useful as a confirmation fallback.
func probeVeeam(ctx context.Context, s *Stack, target Target) (*Result, error) {
	if target.Port == 9419 {
		return probeVeeamREST(ctx, s, target)
	}

	return probeVeeamBanner(ctx, s, target)
}

// probeVeeamREST queries the Veeam B&R REST API serverInfo endpoint.
func probeVeeamREST(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("https://%s/api/v1/serverInfo", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Veeam request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/Veeam")
	req.Header.Set("x-api-version", "1.1-rev1")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Veeam serverInfo: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	if err != nil {
		return nil, fmt.Errorf("can't read Veeam serverInfo body: %w", err)
	}

	var info struct {
		Name         string `json:"name"`
		BuildVersion string `json:"buildVersion"`
		PatchLevel   string `json:"patchLevel"`
	}

	if jsonErr := json.Unmarshal(body, &info); jsonErr != nil || info.BuildVersion == "" {
		serverHdr := resp.Header.Get("Server")

		if !strings.Contains(strings.ToLower(serverHdr+string(body)), "veeam") {
			return &Result{Target: target, Protocol: protocolHTTPS, Banner: string(body)}, nil
		}

		return &Result{
			Target:   target,
			Protocol: productVeeamBackup,
			Banner:   serverHdr,
			Fingerprint: &FingerprintResult{
				Product: productVeeamBackup,
				RawJSON: mustMarshalJSON(map[string]any{
					"server":      serverHdr,
					"http_status": resp.StatusCode,
				}),
			},
		}, nil
	}

	fp := &FingerprintResult{
		Product: productVeeamBackup,
		Version: info.BuildVersion,
		Edition: info.Name,
		RawJSON: body,
	}

	return &Result{
		Target:      target,
		Protocol:    productVeeamBackup,
		Banner:      "Veeam B&R " + info.BuildVersion,
		Fingerprint: fp,
	}, nil
}

// probeVeeamBanner reads the short ASCII greeting Veeam emits on its
// PSExec management socket. Any reply containing "Veeam" is treated as a
// positive.
func probeVeeamBanner(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	buf := make([]byte, 512)

	n, _ := conn.Read(buf)

	banner := strings.TrimRight(string(buf[:n]), "\r\n\x00")

	if !strings.Contains(strings.ToLower(banner), "veeam") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: banner}, nil
	}

	fp := &FingerprintResult{
		Product: productVeeamBackup,
		RawJSON: mustMarshalJSON(map[string]any{"banner": banner}),
	}

	return &Result{
		Target:      target,
		Protocol:    productVeeamBackup,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}
