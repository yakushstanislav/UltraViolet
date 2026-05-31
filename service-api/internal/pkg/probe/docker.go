package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
)

const productDocker = "docker"

func init() {
	// Docker daemon HTTP REST: 2375 (plaintext), 2376 (TLS). The TLS port
	// reuses the same payload — probeHTTPS would catch /version on 2376,
	// but distroless Docker installs frequently expose 2375 explicitly for
	// CI/CD which is exactly the misconfiguration we want to surface.
	Register(probeDocker, 2375)
}

// probeDocker fetches Docker daemon's /version endpoint. The reply is a
// stable JSON document Docker has shipped since v1.0 — see
// https://docs.docker.com/engine/api/v1.43/#tag/System/operation/SystemVersion.
//
// We persist Version + ApiVersion + GoVersion as a FingerprintResult so that
// cvematch can correlate against docker/docker (and moby) CVE feeds.
func probeDocker(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/version", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build docker /version request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/probe")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch docker /version: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	if err != nil {
		return nil, fmt.Errorf("can't read docker /version body: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
	}

	var version struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
		GoVersion  string `json:"GoVersion"`
		Os         string `json:"Os"`
		Arch       string `json:"Arch"`
		KernelVer  string `json:"KernelVersion"`
	}

	if jsonErr := json.Unmarshal(body, &version); jsonErr != nil || version.Version == "" {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
	}

	fp := &FingerprintResult{
		Product: productDocker,
		Version: version.Version,
		Edition: version.APIVersion,
		RawJSON: body,
	}

	if version.Os != "" || version.Arch != "" {
		fp.ClusterRole = version.Os + "/" + version.Arch
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Banner:      string(body),
		Fingerprint: fp,
	}, nil
}
