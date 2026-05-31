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

const productEnvoy = "envoy"

func init() {
	// 9901 — Envoy admin endpoint default port (per envoy.yaml docs).
	Register(probeEnvoyAdmin, 9901)
}

// probeEnvoyAdmin fingerprints an Envoy proxy admin interface using
// /server_info, which returns:
//
//	{
//	  "version":"1.29.1/...",
//	  "state":"LIVE",
//	  "hot_restart_version":"...",
//	  "command_line_options":{...},
//	  "uptime_current_epoch":"...",
//	  "uptime_all_epochs":"..."
//	}
func probeEnvoyAdmin(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/server_info", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Envoy admin request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/Envoy")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Envoy /server_info: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	var info struct {
		Version           string `json:"version"`
		State             string `json:"state"`
		HotRestartVersion string `json:"hot_restart_version"`
	}

	if jsonErr := json.Unmarshal(body, &info); jsonErr != nil || info.Version == "" {
		raw := strings.ToLower(string(body) + " " + resp.Header.Get("Server"))

		if !strings.Contains(raw, "envoy") {
			return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
		}

		return &Result{
			Target:   target,
			Protocol: productEnvoy,
			Banner:   "Envoy admin",
			Fingerprint: &FingerprintResult{
				Product: productEnvoy,
				RawJSON: body,
			},
		}, nil
	}

	version := info.Version

	if idx := strings.IndexByte(version, '/'); idx > 0 {
		version = version[:idx]
	}

	fp := &FingerprintResult{
		Product: productEnvoy,
		Version: version,
		Edition: info.State,
		RawJSON: body,
	}

	return &Result{
		Target:      target,
		Protocol:    productEnvoy,
		Banner:      "Envoy " + version,
		Fingerprint: fp,
	}, nil
}
