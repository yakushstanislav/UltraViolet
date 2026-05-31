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

const productEtcd = "etcd"

func init() {
	// etcd client API. 2380 is the peer port and only speaks Raft RPC, so
	// skip it on purpose — exposing /version there has been a feature
	// request for years but never landed.
	Register(probeEtcd, 2379)
}

// probeEtcd fetches the etcd /version endpoint, available on the client
// API since v3.0: https://etcd.io/docs/v3.5/dev-guide/api_reference_v3/.
// Response shape:
//
//	{"etcdserver":"3.5.10","etcdcluster":"3.5.0"}
//
// We map etcdserver → FingerprintResult.Version so cvematch picks it up via
// the etcd vendor mapping in cpemap.productMap.
func probeEtcd(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/version", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build etcd /version request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/probe")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch etcd /version: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	if err != nil {
		return nil, fmt.Errorf("can't read etcd /version body: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
	}

	var version struct {
		EtcdServer  string `json:"etcdserver"`
		EtcdCluster string `json:"etcdcluster"`
	}

	if jsonErr := json.Unmarshal(body, &version); jsonErr != nil || version.EtcdServer == "" {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
	}

	fp := &FingerprintResult{
		Product: productEtcd,
		Version: version.EtcdServer,
		Edition: version.EtcdCluster,
		RawJSON: body,
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Banner:      string(body),
		Fingerprint: fp,
	}, nil
}
