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

const (
	productEdgeX   = "edgex_foundry"
	edgeXBodyLimit = 64 * 1024
)

// edgeXPingPaths lists the ping endpoints exposed by EdgeX core services
// across the LTS release lines. v1/v2 used /api/v1/ping, v3 (Minnesota
// / Napa / Odessa) switched to /api/v3/ping and returns JSON. We try the
// v3 endpoint first since most production deployments are post-Minnesota.
var edgeXPingPaths = []string{"/api/v3/ping", "/api/v2/ping", "/api/v1/ping"}

func init() {
	// 59880 — core-data (EdgeX v3 default).
	// 48080 — core-data (EdgeX v1/v2 legacy default, still used by a
	//         meaningful share of Dell EMC / IOTech / ZEDEDA gateways).
	Register(probeEdgeX, 48080, 59880)
}

// probeEdgeX hits the EdgeX Foundry ping endpoint, which is reachable
// without authentication on every release line we've seen in the wild.
// EdgeX is a Linux Foundation open-source IoT/IIoT gateway platform that
// underpins Dell Edge Gateways, IOTech Edge Xpert, ZEDEDA EVE-OS device
// fleets and a growing number of factory IoT installs.
//
// Response shapes:
//
//	v3: {"apiVersion":"v3","timestamp":"Mon Jan ..."}
//	v2: {"apiVersion":"v2","timestamp":"Mon Jan ..."}
//	v1: "pong"
//
// We surface apiVersion as Edition (it doubles as the release-line marker
// used for CVE routing) and look opportunistically at the ping body for
// a serviceName field that some forks add.
func probeEdgeX(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	for _, path := range edgeXPingPaths {
		url := fmt.Sprintf("http://%s%s", addr, path)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("can't build EdgeX ping request: %w", err)
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "UltraViolet/probe")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, edgeXBodyLimit))
		_ = resp.Body.Close()

		if readErr != nil || resp.StatusCode/100 != 2 {
			continue
		}

		fp := parseEdgeXPing(body)
		if fp == nil {
			continue
		}

		return &Result{
			Target:      target,
			Protocol:    productEdgeX,
			Banner:      strings.TrimSpace("EdgeX Foundry " + fp.Edition),
			Fingerprint: fp,
		}, nil
	}

	return &Result{Target: target, Protocol: protocolHTTP}, nil
}

// parseEdgeXPing inspects a ping body and returns a fingerprint when it
// matches the EdgeX response shape. Both the JSON (v2/v3) and the bare
// "pong" (v1) variants are accepted; nil is returned for anything else
// so the dispatcher keeps probing other paths or falls through.
func parseEdgeXPing(body []byte) *FingerprintResult {
	trimmed := strings.TrimSpace(string(body))

	if strings.EqualFold(trimmed, "pong") {
		return &FingerprintResult{
			Product: productEdgeX,
			Edition: "v1",
			RawJSON: mustMarshalJSON(map[string]any{"body": trimmed}),
		}
	}

	var payload struct {
		APIVersion  string `json:"apiVersion"`
		Timestamp   string `json:"timestamp"`
		ServiceName string `json:"serviceName"`
		Version     string `json:"version"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}

	if payload.APIVersion == "" && payload.Timestamp == "" {
		return nil
	}

	return &FingerprintResult{
		Product: productEdgeX,
		Version: payload.Version,
		Edition: payload.APIVersion,
		RawJSON: body,
	}
}
