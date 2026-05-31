package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const productLGwebOSTV = "lg_webos_tv"

func init() {
	// LG webOS Smart TVs expose the SSAP control channel on TCP 3000
	// (plain WS) and 3001 (TLS WSS). Port 3000 is already claimed by the
	// generic HTTP prober — derived.go aliases catch "Server: WebOS"
	// banners there. Port 3001 is free, and the LG firmware always
	// presents a TLS leaf cert with O="LG Electronics" / CN="LGSmartTV",
	// which gives us a reliable fingerprint even when the WebSocket
	// upgrade is refused.
	Register(probeWebOSTV, 3001)
}

// probeWebOSTV detects LG webOS televisions and set-top boxes. The TV
// answers an HTTPS GET on the root path with either an empty body and
// "Server: WebOS" or a JSON-ish error string that mentions "webOS"; the
// definitive marker, however, is the self-signed TLS cert whose
// Subject/Issuer carries "LG Electronics" and a SAN such as
// "LGSmartTV-<MAC>".
func probeWebOSTV(ctx context.Context, s *Stack, target Target) (*Result, error) {
	tlsResult, err := s.handshakeTLS(ctx, target)
	if err != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	endpoint := fmt.Sprintf("https://%s/", addr)

	client := &http.Client{
		Transport: s.httpTransport,
		Timeout:   s.probeTimeout(ctx),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if reqErr != nil {
		return webOSResultFromTLS(target, tlsResult), nil
	}

	req.Header.Set("User-Agent", "UltraViolet/webOS")

	resp, doErr := client.Do(req)
	if doErr != nil {
		return webOSResultFromTLS(target, tlsResult), nil
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	server := resp.Header.Get("Server")

	if !looksLikeWebOS(server, body, tlsResult) {
		return &Result{
			Target:   target,
			Protocol: protocolHTTPS,
			Banner:   strings.TrimSpace(server),
			TLS:      tlsResult,
		}, nil
	}

	banner := strings.TrimSpace(server)
	if banner == "" {
		banner = "LG webOS TV"
	}

	fp := &FingerprintResult{
		Product: productLGwebOSTV,
		Version: extractWebOSVersion(server, string(body)),
		RawJSON: mustMarshalJSON(map[string]any{
			"http_status":   resp.StatusCode,
			"server_header": server,
			"tls_subject":   safeTLSSubject(tlsResult),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productLGwebOSTV,
		Banner:      banner,
		TLS:         tlsResult,
		Fingerprint: fp,
	}, nil
}

// webOSResultFromTLS keeps the TLS material when the HTTPS GET phase
// failed but the TLS leaf already carries LG-specific markers. The
// downstream tlsSubjectHint hop in stack.go gives derived.go a second
// chance to recognise the device.
func webOSResultFromTLS(target Target, tlsResult *TLSResult) *Result {
	if tlsResult == nil {
		return &Result{Target: target, Protocol: protocolTCP}
	}

	fp := tlsSubjectHint(tlsResult)

	result := &Result{
		Target:   target,
		Protocol: protocolHTTPS,
		TLS:      tlsResult,
	}

	if fp != nil {
		result.Protocol = fp.Product
		result.Fingerprint = fp
	}

	return result
}

// looksLikeWebOS returns true when Server, body, or TLS Subject contains
// one of the LG webOS firmware markers. Subject hits alone are enough —
// the LG production CA chain consistently embeds "LG Electronics".
func looksLikeWebOS(server string, body []byte, tlsResult *TLSResult) bool {
	lowerServer := strings.ToLower(server)
	if strings.Contains(lowerServer, "webos") || strings.Contains(lowerServer, "lg ") || strings.Contains(lowerServer, "lg-") {
		return true
	}

	lowerBody := strings.ToLower(string(body))
	if strings.Contains(lowerBody, "webos") || strings.Contains(lowerBody, "lgsmarttv") {
		return true
	}

	if tlsResult == nil {
		return false
	}

	subj := strings.ToLower(tlsResult.Subject + " " + tlsResult.Issuer + " " + strings.Join(tlsResult.SANs, " "))

	return strings.Contains(subj, "lg electronics") || strings.Contains(subj, "lgsmarttv") || strings.Contains(subj, "webos")
}

// extractWebOSVersion pulls a version token out of either the Server
// header ("WebOS/6.3.0") or a body fragment ("webOSTV/24.0.0"). Empty
// when no version-looking string is present.
func extractWebOSVersion(server, body string) string {
	for _, candidate := range []string{server, body} {
		if match := productAndVersionRE.FindStringSubmatch(candidate); len(match) == 3 {
			if strings.Contains(strings.ToLower(match[1]), "webos") {
				return match[2]
			}
		}
	}

	return ""
}

// safeTLSSubject is a defensive accessor — earlier failure paths may
// have nil-ed the TLS field, and the JSON marshaller is happy to take
// an empty string.
func safeTLSSubject(t *TLSResult) string {
	if t == nil {
		return ""
	}

	return t.Subject
}
