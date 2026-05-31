package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const productSamsungTizenTV = "samsung_tizen_tv"

func init() {
	// 8001 = plain HTTP wrapper around the Samsung Tizen Remote API
	// (WebSocket on /api/v2/channels/...). 8002 is the TLS-protected
	// variant introduced with Tizen 4 — both ports advertise the same
	// /api/v2/ JSON descriptor, so we share one prober.
	Register(probeSamsungTV, 8001, 8002)
}

// probeSamsungTV detects Samsung Tizen Smart TVs (and Family Hub fridge
// panels, which reuse the same firmware shell) by hitting the Smart View
// API's device descriptor at /api/v2/. The payload returned by every
// supported model is a small JSON document of the shape:
//
//	{
//	  "id": "uuid:...",
//	  "isSupport": "{ ... }",
//	  "name": "[TV] Living Room",
//	  "remote": "1.0",
//	  "type": "Samsung SmartTV",
//	  "version": "2.0.25",
//	  "device": {
//	    "modelName": "UE55KU6400",
//	    "tokenSupport": "true",
//	    "wifiMac": "AA:BB:..."
//	  }
//	}
//
// version maps onto Tizen firmware revisions and tokenSupport=true is a
// strong signal that the TV is running Tizen 4+, where CVE-2022-23728
// and the 2023 Smart Hub RCE chain apply.
func probeSamsungTV(ctx context.Context, s *Stack, target Target) (*Result, error) {
	scheme := protocolHTTP
	if target.Port == 8002 {
		scheme = protocolHTTPS
	}

	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	endpoint := fmt.Sprintf("%s://%s/api/v2/", scheme, addr)

	client := &http.Client{
		Transport: s.httpTransport,
		Timeout:   s.probeTimeout(ctx),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	req.Header.Set("User-Agent", "UltraViolet/SamsungTV")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

	tlsResult := captureTLSFromResponse(resp)

	var info samsungTVInfo

	if jsonErr := json.Unmarshal(body, &info); jsonErr != nil || !looksLikeSamsungTV(info, resp.Header, body) {
		return samsungTVFallback(target, resp, body, tlsResult), nil
	}

	tokenSupport := strings.EqualFold(info.Device.TokenSupport, "true")
	authRequired := tokenSupport

	model := strings.TrimSpace(info.Device.ModelName)

	banner := strings.TrimSpace(info.Type + " " + model)
	if banner == "" {
		banner = "Samsung Tizen TV"
	}

	fp := &FingerprintResult{
		Product:      productSamsungTizenTV,
		Version:      strings.TrimSpace(info.Version),
		Edition:      model,
		AuthRequired: &authRequired,
		RawJSON: mustMarshalJSON(map[string]any{
			"http_status":   resp.StatusCode,
			"name":          info.Name,
			"type":          info.Type,
			"remote":        info.Remote,
			"version":       info.Version,
			"model_name":    model,
			"token_support": info.Device.TokenSupport,
			"os":            info.Device.OS,
			"firmware":      info.Device.FirmwareVersion,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productSamsungTizenTV,
		Banner:      banner,
		TLS:         tlsResult,
		Fingerprint: fp,
	}, nil
}

// samsungTVInfo mirrors the subset of /api/v2/ fields we use. Samsung
// stringifies booleans and ships nested device metadata under "device".
type samsungTVInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Remote string `json:"remote"`
	Type   string `json:"type"`
	URI    string `json:"uri"`
	// Samsung reports "version" both at the root (Smart View API version)
	// and inside the device block (firmware) — we capture both.
	Version string `json:"version"`
	Device  struct {
		ModelName       string `json:"modelName"`
		TokenSupport    string `json:"tokenSupport"`
		OS              string `json:"OS"`
		FirmwareVersion string `json:"FrameTVSupport"`
		Type            string `json:"type"`
		WifiMac         string `json:"wifiMac"`
	} `json:"device"`
}

// looksLikeSamsungTV guards against false positives — any HTTP server at
// /api/v2/ can return JSON; we only commit to the Tizen TV identity when
// either the type field or a Samsung-flavoured Server header confirms it.
func looksLikeSamsungTV(info samsungTVInfo, headers http.Header, body []byte) bool {
	if strings.Contains(strings.ToLower(info.Type), "samsung") {
		return true
	}

	if info.Device.ModelName != "" && info.Device.TokenSupport != "" {
		return true
	}

	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "tizen") || strings.Contains(server, "samsung") {
		return true
	}

	lowerBody := strings.ToLower(string(body))

	return strings.Contains(lowerBody, "samsung smarttv") || strings.Contains(lowerBody, "tizen")
}

// samsungTVFallback returns a generic HTTP-ish result when /api/v2/ did
// not produce a recognisable Samsung descriptor. It still keeps the TLS
// metadata so derived.go's tlsSubjectHint can pick up a "Samsung
// Electronics" Subject downstream.
func samsungTVFallback(target Target, resp *http.Response, body []byte, tlsResult *TLSResult) *Result {
	server := resp.Header.Get("Server")
	banner := strings.TrimSpace(server)

	protocol := protocolHTTP
	if target.Port == 8002 {
		protocol = protocolHTTPS
	}

	result := &Result{
		Target:   target,
		Protocol: protocol,
		Banner:   banner,
		TLS:      tlsResult,
	}

	httpResult := &HTTPResult{
		StatusCode: resp.StatusCode,
		Server:     server,
		Headers:    flattenHeaders(resp.Header),
		Body:       string(body),
	}

	if fp := fingerprintFromHTTP(httpResult); fp != nil {
		result.Protocol = fp.Product
		result.Fingerprint = fp
	}

	return result
}

// captureTLSFromResponse pulls the leaf certificate out of resp.TLS when
// the request travelled over TLS. Returns nil for plain HTTP requests so
// the caller can leave TLS unset.
func captureTLSFromResponse(resp *http.Response) *TLSResult {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}

	result := leafCertToResult(resp.TLS.PeerCertificates[0])
	result.TLSVersion = tls.VersionName(resp.TLS.Version)
	result.CipherSuite = tls.CipherSuiteName(resp.TLS.CipherSuite)

	return result
}
