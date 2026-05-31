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

const productChromecast = "google_chromecast"

func init() {
	// 8008 = the plain-HTTP Eureka/Setup API every Cast receiver (Google
	// Home, Chromecast, Nest Hub, Android TV, JBL/LG/Sony Cast-enabled
	// soundbars) exposes. 8009 = the binary Cast Channel (protobuf over
	// TLS). We probe both — 8008 yields the full device descriptor,
	// 8009 yields a self-signed TLS leaf signed by "Chromecast ICA"
	// that's already a strong fingerprint by itself.
	Register(probeChromecast, 8008, 8009)
}

// probeChromecast detects Google Cast / Android TV / Nest devices.
//
// For 8008 we GET /setup/eureka_info?options=detail and parse the JSON
// payload — the response shape is:
//
//	{
//	  "build_version": "1.56.275994",
//	  "cast_build_revision": "1.56.275994",
//	  "name": "Living Room",
//	  "ssdp_udn": "...",
//	  "version": 9,
//	  "release_track": "stable-channel",
//	  "device_info": {
//	    "model_name": "Chromecast",
//	    "manufacturer": "Google Inc.",
//	    "product_name": "eureka"
//	  }
//	}
//
// For 8009 we fall back to a TLS handshake and read the leaf subject —
// it always reads "CN=Chromecast ICA <serial>" issued by
// "Cast Root CA".
func probeChromecast(ctx context.Context, s *Stack, target Target) (*Result, error) {
	if target.Port == 8009 {
		return chromecastTLS(ctx, s, target)
	}

	if result, ok := chromecastEureka(ctx, s, target); ok {
		return result, nil
	}

	if result, tlsErr := chromecastTLS(ctx, s, target); tlsErr == nil {
		return result, nil
	}

	return &Result{Target: target, Protocol: protocolTCP}, nil
}

// chromecastEureka issues Eureka / DIAL HTTP descriptor requests. The bool
// reports whether a Cast fingerprint was produced.
func chromecastEureka(ctx context.Context, s *Stack, target Target) (*Result, bool) {
	paths := []string{
		"/setup/eureka_info?options=detail",
		"/setup/eureka_info",
		"/ssdp/device-desc.xml",
		"/",
	}

	client := &http.Client{
		Transport: s.httpTransport,
		Timeout:   s.probeTimeout(ctx),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	for _, path := range paths {
		endpoint := fmt.Sprintf("http://%s%s", addr, path)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "UltraViolet/Cast")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

		_ = resp.Body.Close()

		var info chromecastEurekaInfo

		if jsonErr := json.Unmarshal(body, &info); jsonErr != nil || !looksLikeChromecast(info, resp.Header) {
			continue
		}

		model := strings.TrimSpace(info.DeviceInfo.ModelName)
		if model == "" {
			model = strings.TrimSpace(info.ModelName)
		}

		banner := strings.TrimSpace("Google Cast " + model)

		version := strings.TrimSpace(info.CastBuildRevision)
		if version == "" {
			version = strings.TrimSpace(info.BuildVersion)
		}

		fp := &FingerprintResult{
			Product: productChromecast,
			Version: version,
			Edition: model,
			RawJSON: mustMarshalJSON(map[string]any{
				"http_status":         resp.StatusCode,
				"path":                path,
				"name":                info.Name,
				"build_version":       info.BuildVersion,
				"cast_build_revision": info.CastBuildRevision,
				"release_track":       info.ReleaseTrack,
				"model_name":          model,
				"manufacturer":        info.DeviceInfo.Manufacturer,
				"product_name":        info.DeviceInfo.ProductName,
				"version":             info.Version,
			}),
		}

		return &Result{
			Target:      target,
			Protocol:    productChromecast,
			Banner:      banner,
			Fingerprint: fp,
		}, true
	}

	return &Result{Target: target, Protocol: protocolTCP}, false
}

// chromecastTLS handles the binary Cast Channel port. We only complete
// the TLS handshake — the protocol on top is protobuf framed with a
// 4-byte big-endian length, and the device refuses to talk until the
// client authenticates with a device-specific certificate.
func chromecastTLS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	tlsResult, err := s.handshakeTLS(ctx, target)
	if err != nil {
		return nil, err
	}

	subject := strings.ToLower(tlsResult.Subject + " " + tlsResult.Issuer)
	confirmed := strings.Contains(subject, "chromecast") ||
		strings.Contains(subject, "cast root ca") ||
		strings.Contains(subject, "google")

	result := &Result{
		Target:   target,
		Protocol: protocolHTTPS,
		Banner:   tlsResult.Subject,
		TLS:      tlsResult,
	}

	if confirmed {
		result.Protocol = productChromecast
		result.Fingerprint = &FingerprintResult{
			Product: productChromecast,
			RawJSON: mustMarshalJSON(map[string]any{
				"tls_subject": tlsResult.Subject,
				"tls_issuer":  tlsResult.Issuer,
				"port":        target.Port,
			}),
		}
	}

	return result, nil
}

// chromecastEurekaInfo captures the subset of /setup/eureka_info fields
// we read. Google occasionally renames inner fields between firmware
// generations, so we look at both root-level and device_info-nested
// model names.
type chromecastEurekaInfo struct {
	Name              string `json:"name"`
	BuildVersion      string `json:"build_version"`
	CastBuildRevision string `json:"cast_build_revision"`
	ReleaseTrack      string `json:"release_track"`
	Version           int    `json:"version"`
	ModelName         string `json:"model_name"`
	HotspotBSSID      string `json:"hotspot_bssid"`
	DeviceInfo        struct {
		ModelName    string `json:"model_name"`
		Manufacturer string `json:"manufacturer"`
		ProductName  string `json:"product_name"`
		SSDPUDN      string `json:"ssdp_udn"`
	} `json:"device_info"`
}

// looksLikeChromecast confirms the response really came from a Cast
// receiver — a stray HTTP server returning 200 on the Eureka path is
// unlikely, but we still cross-check at least one identifying field.
func looksLikeChromecast(info chromecastEurekaInfo, headers http.Header) bool {
	if info.CastBuildRevision != "" || info.BuildVersion != "" {
		return true
	}

	if info.DeviceInfo.Manufacturer != "" || info.DeviceInfo.ModelName != "" {
		return true
	}

	server := strings.ToLower(headers.Get("Server"))

	return strings.Contains(server, "eureka") || strings.Contains(server, "chromecast")
}
