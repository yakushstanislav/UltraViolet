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

const productIstioPilot = "istio_pilot"

func init() {
	// 15014 — istiod debug HTTP. Ports 15010 (xDS gRPC plaintext) and
	// 15012 (xDS gRPC TLS) require a gRPC client; debug HTTP is the
	// fingerprint-friendly path.
	Register(probeIstioPilot, 15014)
}

// probeIstioPilot fingerprints istiod via /version:
//
//	{
//	  "version":"1.20.3",
//	  "revision":"...",
//	  "golang_version":"go1.21.5",
//	  "build_status":"Clean"
//	}
func probeIstioPilot(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/version", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build istiod request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/Istio")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch istiod /version: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	var info struct {
		Version       string `json:"version"`
		Revision      string `json:"revision"`
		GolangVersion string `json:"golang_version"`
		BuildStatus   string `json:"build_status"`
	}

	if jsonErr := json.Unmarshal(body, &info); jsonErr != nil || info.Version == "" {
		raw := strings.ToLower(string(body))

		if !strings.Contains(raw, "istio") && !strings.Contains(raw, "pilot") {
			return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
		}

		return &Result{
			Target:   target,
			Protocol: productIstioPilot,
			Banner:   "istiod",
			Fingerprint: &FingerprintResult{
				Product: productIstioPilot,
				RawJSON: body,
			},
		}, nil
	}

	fp := &FingerprintResult{
		Product: productIstioPilot,
		Version: info.Version,
		Edition: info.Revision,
		RawJSON: body,
	}

	return &Result{
		Target:      target,
		Protocol:    productIstioPilot,
		Banner:      "Istio Pilot " + info.Version,
		Fingerprint: fp,
	}, nil
}
