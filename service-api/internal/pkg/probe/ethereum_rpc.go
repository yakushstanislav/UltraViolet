package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const productEthereumGeth = "ethereum_geth"

func init() {
	// 8545 — Ethereum JSON-RPC over HTTP. devp2p RLPx 30303 is
	// encrypted and infeasible to probe synchronously.
	Register(probeEthereumRPC, 8545)
}

// probeEthereumRPC POSTs a `web3_clientVersion` call to an Ethereum
// JSON-RPC endpoint. Geth replies with `"Geth/v1.13.14-..."`,
// Erigon/OpenEthereum/Besu/Nethermind each ship their own prefix.
func probeEthereumRPC(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s/", addr)

	payload := `{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, fmt.Errorf("can't build Ethereum RPC request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/Ethereum")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't POST Ethereum RPC: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))

	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		Result  string `json:"result"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if jsonErr := json.Unmarshal(body, &envelope); jsonErr != nil {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
	}

	clientStr := envelope.Result

	product := productEthereumGeth

	if hint := ethereumClientHint(clientStr); hint != "" {
		product = hint
	}

	version := extractEthereumVersion(clientStr)

	fp := &FingerprintResult{
		Product: product,
		Version: version,
		Edition: clientStr,
		RawJSON: body,
	}

	if clientStr == "" && envelope.Error.Code == 0 {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: string(body)}, nil
	}

	banner := clientStr
	if banner == "" {
		banner = "Ethereum JSON-RPC"
	}

	return &Result{
		Target:      target,
		Protocol:    product,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// ethereumClientHint maps known Ethereum client banners onto cpemap keys.
func ethereumClientHint(clientStr string) string {
	lower := strings.ToLower(clientStr)

	switch {
	case strings.HasPrefix(lower, "geth/"):
		return productEthereumGeth
	case strings.HasPrefix(lower, "erigon/"):
		return "ethereum_erigon"
	case strings.HasPrefix(lower, "openethereum/"), strings.HasPrefix(lower, "parity/"):
		return "ethereum_openethereum"
	case strings.HasPrefix(lower, "besu/"):
		return "hyperledger_besu"
	case strings.HasPrefix(lower, "nethermind/"):
		return "ethereum_nethermind"
	case strings.Contains(lower, "lighthouse"):
		return "ethereum_lighthouse"
	case strings.Contains(lower, "prysm"):
		return "ethereum_prysm"
	}

	return ""
}

// extractEthereumVersion pulls the canonical version token out of an
// Ethereum client banner: "Geth/v1.13.14-..." → "1.13.14".
func extractEthereumVersion(s string) string {
	idx := strings.Index(s, "/v")
	if idx < 0 {
		idx = strings.IndexByte(s, '/')
		if idx < 0 {
			return ""
		}

		idx++
	} else {
		idx += 2
	}

	tail := s[idx:]
	end := len(tail)

	for i, c := range tail {
		if c == '-' || c == '/' || c == ' ' || c == '(' {
			end = i

			break
		}
	}

	if end == 0 || tail[0] < '0' || tail[0] > '9' {
		return ""
	}

	return tail[:end]
}
