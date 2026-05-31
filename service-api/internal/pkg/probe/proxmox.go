package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const productProxmoxVE = "proxmox_ve"

func init() {
	// 8006 is the HTTPS port of the Proxmox VE web UI / API2. It is the
	// only Proxmox port the probeHTTPS registry does not already cover,
	// since 8443 is reserved by the standard HTTPS registration.
	Register(probeProxmoxVE, 8006)
}

// probeProxmoxVE fingerprints Proxmox VE through its public API endpoint
// `/api2/json/version`, which returns
//
//	{"data":{"version":"8.1.4","release":"8.1","repoid":"..."}}
//
// even on hosts that require auth for the rest of the API. The TLS leaf
// is captured to help the catalog lookups even if the API is firewalled.
func probeProxmoxVE(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	tlsResult, _ := proxmoxHandshake(ctx, s, addr)

	url := fmt.Sprintf("https://%s/api2/json/version", addr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Proxmox version request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/Proxmox")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		if tlsResult != nil {
			return &Result{
				Target:   target,
				Protocol: protocolHTTPS,
				TLS:      tlsResult,
			}, nil
		}

		return nil, fmt.Errorf("can't fetch Proxmox /api2/json/version: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.cfg.MaxBody)))
	if err != nil {
		return nil, fmt.Errorf("can't read Proxmox version body: %w", err)
	}

	var envelope struct {
		Data struct {
			Version string `json:"version"`
			Release string `json:"release"`
			RepoID  string `json:"repoid"`
		} `json:"data"`
	}

	if jsonErr := json.Unmarshal(body, &envelope); jsonErr != nil || envelope.Data.Version == "" {
		// 401 with HTML pveproxy banner is still a positive hit.
		serverHdr := resp.Header.Get("Server")

		if strings.Contains(strings.ToLower(serverHdr), "pve-api") ||
			strings.Contains(strings.ToLower(string(body)), "proxmox") {
			return &Result{
				Target:   target,
				Protocol: productProxmoxVE,
				Banner:   serverHdr,
				TLS:      tlsResult,
				Fingerprint: &FingerprintResult{
					Product: productProxmoxVE,
					RawJSON: mustMarshalJSON(map[string]any{
						"server":      serverHdr,
						"http_status": resp.StatusCode,
					}),
				},
			}, nil
		}

		return &Result{Target: target, Protocol: protocolHTTPS, TLS: tlsResult, Banner: string(body)}, nil
	}

	fp := &FingerprintResult{
		Product: productProxmoxVE,
		Version: envelope.Data.Version,
		Edition: envelope.Data.Release,
		RawJSON: body,
	}

	return &Result{
		Target:      target,
		Protocol:    productProxmoxVE,
		Banner:      "Proxmox VE " + envelope.Data.Version,
		TLS:         tlsResult,
		Fingerprint: fp,
	}, nil
}

// proxmoxHandshake captures the leaf cert without committing to a full
// TLS-only result path; the caller still goes on to issue the HTTPS GET.
func proxmoxHandshake(ctx context.Context, s *Stack, addr string) (*TLSResult, error) {
	netDialer := &net.Dialer{Timeout: s.cfg.Timeout}

	conn, err := (&tls.Dialer{
		NetDialer: netDialer,
		Config:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // scanner probes arbitrary hosts
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("non-TLS conn returned from TLS dial")
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("TLS handshake returned no certificates")
	}

	leaf := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(leaf.Raw)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	return &TLSResult{
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		RawPEM:            string(pemBytes),
		SANs:              leaf.DNSNames,
		TLSVersion:        tls.VersionName(state.Version),
		CipherSuite:       tls.CipherSuiteName(state.CipherSuite),
	}, nil
}
