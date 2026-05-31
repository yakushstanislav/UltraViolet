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

const productGoCD = "gocd"

func init() {
	// 8153 — GoCD server HTTP. 8154 is the HTTPS twin (probeHTTPS would
	// not register it by default but generic 4-digit HTTPS hosts often
	// fall through here too — we keep 8154 too for symmetry).
	Register(probeGoCD, 8153, 8154)
}

// probeGoCD fingerprints a GoCD server through /go/api/version, which
// always returns:
//
//	{
//	  "version":"23.4.0",
//	  "build_number":"...",
//	  "git_sha":"...",
//	  "full_version":"23.4.0 (15981-...)"
//	}
//
// regardless of authentication state.
func probeGoCD(ctx context.Context, s *Stack, target Target) (*Result, error) {
	scheme := "http"
	if target.Port == 8154 {
		scheme = "https"
	}

	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("%s://%s/go/api/version", scheme, addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build GoCD request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.go.cd+json")
	req.Header.Set("User-Agent", "UltraViolet/GoCD")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch GoCD version: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	var info struct {
		Version     string `json:"version"`
		BuildNumber string `json:"build_number"`
		GitSHA      string `json:"git_sha"`
		FullVersion string `json:"full_version"`
	}

	if jsonErr := json.Unmarshal(body, &info); jsonErr != nil || info.Version == "" {
		lower := strings.ToLower(string(body) + " " + resp.Header.Get("Server"))

		if !strings.Contains(lower, "gocd") && !strings.Contains(lower, "go-server") {
			return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
		}

		return &Result{
			Target:   target,
			Protocol: productGoCD,
			Banner:   "GoCD",
			Fingerprint: &FingerprintResult{
				Product: productGoCD,
				RawJSON: body,
			},
		}, nil
	}

	fp := &FingerprintResult{
		Product: productGoCD,
		Version: info.Version,
		Edition: info.BuildNumber,
		RawJSON: body,
	}

	return &Result{
		Target:      target,
		Protocol:    productGoCD,
		Banner:      "GoCD " + info.FullVersion,
		Fingerprint: fp,
	}, nil
}
