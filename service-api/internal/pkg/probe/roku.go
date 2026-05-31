package probe

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const productRokuTV = "roku_tv"

func init() {
	// 8060 is the External Control Protocol (ECP) port — Roku TVs,
	// Streaming Sticks, Express boxes and OEM TCL/Hisense/Sharp/Insignia
	// builds all answer the /query/device-info path with an XML
	// descriptor that exposes the firmware version, model, network
	// settings and the friendly name set by the owner.
	Register(probeRoku, 8060)
}

// probeRoku hits /query/device-info and parses the XML response. A
// typical payload reads:
//
//	<device-info>
//	  <udn>...</udn>
//	  <serial-number>...</serial-number>
//	  <model-name>Roku Express 4K</model-name>
//	  <model-number>3940X</model-number>
//	  <vendor-name>Roku</vendor-name>
//	  <software-version>12.5.5</software-version>
//	  <software-build>4239</software-build>
//	  <friendly-device-name>Bedroom TV</friendly-device-name>
//	  ...
//	</device-info>
//
// software-version directly matches Roku OS release CVE coordinates;
// model-number tells cvematch whether the firmware-specific CVE for, say,
// "3940X" applies.
func probeRoku(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	endpoint := fmt.Sprintf("http://%s/query/device-info", addr)

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

	req.Header.Set("User-Agent", "UltraViolet/Roku")

	resp, err := client.Do(req)
	if err != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	server := resp.Header.Get("Server")

	var info rokuDeviceInfo

	if xmlErr := xml.Unmarshal(body, &info); xmlErr != nil || !looksLikeRoku(info, server) {
		return &Result{
			Target:   target,
			Protocol: protocolHTTP,
			Banner:   strings.TrimSpace(server),
		}, nil
	}

	model := strings.TrimSpace(info.ModelName)
	if model == "" {
		model = strings.TrimSpace(info.ModelNumber)
	}

	banner := strings.TrimSpace("Roku " + model)

	fp := &FingerprintResult{
		Product: productRokuTV,
		Version: strings.TrimSpace(info.SoftwareVersion),
		Edition: model,
		RawJSON: mustMarshalJSON(map[string]any{
			"http_status":      resp.StatusCode,
			"server_header":    server,
			"udn":              info.UDN,
			"serial_number":    info.SerialNumber,
			"model_name":       info.ModelName,
			"model_number":     info.ModelNumber,
			"vendor_name":      info.VendorName,
			"software_version": info.SoftwareVersion,
			"software_build":   info.SoftwareBuild,
			"friendly_name":    info.FriendlyDeviceName,
			"device_id":        info.DeviceID,
			"network_type":     info.NetworkType,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productRokuTV,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// rokuDeviceInfo mirrors the documented ECP response shape:
// https://developer.roku.com/docs/developer-program/dev-tools/external-control-api.md
type rokuDeviceInfo struct {
	XMLName            xml.Name `xml:"device-info"`
	UDN                string   `xml:"udn"`
	SerialNumber       string   `xml:"serial-number"`
	DeviceID           string   `xml:"device-id"`
	ModelName          string   `xml:"model-name"`
	ModelNumber        string   `xml:"model-number"`
	VendorName         string   `xml:"vendor-name"`
	SoftwareVersion    string   `xml:"software-version"`
	SoftwareBuild      string   `xml:"software-build"`
	FriendlyDeviceName string   `xml:"friendly-device-name"`
	NetworkType        string   `xml:"network-type"`
	NetworkName        string   `xml:"network-name"`
}

// looksLikeRoku makes sure we don't blindly trust any XML parsed at
// /query/device-info. At least the vendor field or a Server header that
// mentions Roku has to confirm the device.
func looksLikeRoku(info rokuDeviceInfo, server string) bool {
	if strings.Contains(strings.ToLower(info.VendorName), "roku") {
		return true
	}

	if info.SoftwareVersion != "" && info.ModelNumber != "" {
		return true
	}

	lower := strings.ToLower(server)

	return strings.Contains(lower, "roku")
}
