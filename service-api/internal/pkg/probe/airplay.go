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

const productAppleTV = "apple_tv"

func init() {
	// AirPlay 2 control channel — Apple TV, HomePod, AirPort Express,
	// most modern receivers and a growing list of third-party AirPlay
	// licencees (LG, Sony, Vizio, Roku) advertise themselves on TCP
	// 7000 with the `Server: AirTunes/<version>` header even before any
	// pairing happens, which is exactly what we want for fingerprinting.
	Register(probeAirPlay, 7000)
}

// probeAirPlay issues an HTTP GET on /info — the request the standard
// AirPlay 2 client sends right after dial. Replies are typically a
// binary plist with the receiver's model, firmware, and supported
// features, but for fingerprinting we only need the Server header
// (always present, always carries AirTunes/AirPlay tokens) plus any
// printable substring from the body.
func probeAirPlay(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	endpoint := fmt.Sprintf("http://%s/info", addr)

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

	req.Header.Set("User-Agent", "AirPlay/UltraViolet")

	resp, err := client.Do(req)
	if err != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))

	server := resp.Header.Get("Server")
	if !looksLikeAirPlay(server, body) {
		return &Result{
			Target:   target,
			Protocol: protocolHTTP,
			Banner:   strings.TrimSpace(server),
		}, nil
	}

	version := extractAirPlayVersion(server)
	model := extractAirPlayModel(body)

	banner := strings.TrimSpace(server)
	if banner == "" {
		banner = "AirPlay"
	}

	fp := &FingerprintResult{
		Product: productAppleTV,
		Version: version,
		Edition: model,
		RawJSON: mustMarshalJSON(map[string]any{
			"http_status":   resp.StatusCode,
			"server_header": server,
			"model":         model,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productAppleTV,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// looksLikeAirPlay flags responses whose Server token or body fragment
// matches the AirPlay/AirTunes family. Body content is mostly binary
// plist so we only fall back to it when the Server header is empty.
func looksLikeAirPlay(server string, body []byte) bool {
	lower := strings.ToLower(server)
	if strings.Contains(lower, "airtunes") || strings.Contains(lower, "airplay") {
		return true
	}

	lowerBody := strings.ToLower(string(body))

	return strings.Contains(lowerBody, "airplay") || strings.Contains(lowerBody, "airtunes")
}

// extractAirPlayVersion pulls a numeric token out of "AirTunes/660.6.1"
// or "AirPlay/2.0". Empty when neither pattern matches.
func extractAirPlayVersion(server string) string {
	if match := productAndVersionRE.FindStringSubmatch(server); len(match) == 3 {
		lower := strings.ToLower(match[1])
		if strings.Contains(lower, "airtunes") || strings.Contains(lower, "airplay") {
			return match[2]
		}
	}

	return ""
}

// extractAirPlayModel scans the binary plist for the "model" key value.
// Binary plists store strings as UTF-8 runs, so a substring search is
// good enough for fingerprinting: typical models read "AppleTV3,2",
// "AppleTV5,3", "AudioAccessory1,1" (HomePod), "Receiver4,1" (third-
// party AirPlay 2 receivers).
func extractAirPlayModel(body []byte) string {
	text := string(body)

	for _, marker := range []string{"AppleTV", "AudioAccessory", "Receiver", "iPad", "iPhone"} {
		if idx := strings.Index(text, marker); idx >= 0 {
			end := idx
			for end < len(text) && end-idx < 32 && isModelByte(text[end]) {
				end++
			}

			if end > idx+len(marker) {
				return text[idx:end]
			}
		}
	}

	return ""
}

// isModelByte allows the printable runes Apple uses in model
// identifiers: ASCII letters, digits, and the comma separator.
func isModelByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == ',':
		return true
	}

	return false
}
