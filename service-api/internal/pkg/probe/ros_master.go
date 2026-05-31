package probe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const productROSMaster = "ros_master"

func init() {
	// 11311 — ROS 1 master XML-RPC. ROS 2 uses DDS multicast, which
	// cannot be probed reliably with a synchronous TCP scanner.
	Register(probeROSMaster, 11311)
}

// probeROSMaster issues an XML-RPC `getSystemState` call against a ROS 1
// master. Even when the master rejects unknown callers, the XML-RPC
// transport itself (HTTP envelope + the `<methodResponse>` skeleton)
// proves we are talking to a ROS master.
func probeROSMaster(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/", addr)

	xml := `<?xml version="1.0"?>
<methodCall>
  <methodName>getSystemState</methodName>
  <params>
    <param><value><string>uv-probe</string></value></param>
  </params>
</methodCall>`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(xml)))
	if err != nil {
		return nil, fmt.Errorf("can't build ROS master request: %w", err)
	}

	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("User-Agent", "UltraViolet/ROS")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't POST to ROS master: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	raw := string(body)
	lower := strings.ToLower(raw)

	if !strings.Contains(lower, "methodresponse") && !strings.Contains(lower, "ros") {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: raw}, nil
	}

	fp := &FingerprintResult{
		Product: productROSMaster,
		RawJSON: mustMarshalJSON(map[string]any{
			"http_status": resp.StatusCode,
			"snippet":     firstLine(raw),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productROSMaster,
		Banner:      "ROS master XML-RPC",
		Fingerprint: fp,
	}, nil
}
