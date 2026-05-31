package probe

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const (
	productWeMo    = "belkin_wemo"
	wemoSetupXML   = "/setup.xml"
	wemoBodyLimit  = 256 * 1024
	wemoVendorHint = "belkin"
)

func init() {
	// Belkin WeMo Insight, Switch, Bulb, Mini, Maker and Dimmer firmware
	// runs a tiny UPnP HTTP server on 49152/49153/49154 — the exact port
	// is decided by the device on each boot, so we register all three.
	Register(probeWeMo, 49152, 49153, 49154)
}

// probeWeMo fetches the WeMo UPnP setup XML at /setup.xml. The document
// follows the UPnP 1.0 device description schema and exposes:
//   - <manufacturer>Belkin International Inc.</manufacturer>
//   - <modelName>Socket</modelName> (or LightSwitch, Maker, Bridge…)
//   - <modelNumber>F7C027</modelNumber>
//   - <firmwareVersion>WeMo_WW_2.00.11451.PVT-OWRT-Insight</firmwareVersion>
//   - <serialNumber>22150…</serialNumber>
//
// Several CVEs (CVE-2014-1635, CVE-2018-6692, CVE-2019-17094) are pinned
// to specific firmwareVersion strings, so we capture it verbatim — the
// version is the most actionable field for downstream CVE matching.
func probeWeMo(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s%s", addr, wemoSetupXML)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build WeMo setup request: %w", err)
	}

	req.Header.Set("User-Agent", "UltraViolet/probe")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch WeMo setup: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	limit := int64(s.cfg.MaxBody)
	if limit <= 0 || limit > wemoBodyLimit {
		limit = wemoBodyLimit
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("can't read WeMo setup body: %w", err)
	}

	server := resp.Header.Get("Server")

	if resp.StatusCode/100 != 2 || !looksLikeWeMo(body, server) {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: server}, nil
	}

	dev, err := parseWeMoSetup(body)
	if err != nil {
		return &Result{Target: target, Protocol: productWeMo, Banner: server}, nil
	}

	fp := &FingerprintResult{
		Product: productWeMo,
		Version: dev.FirmwareVersion,
		Edition: strings.TrimSpace(dev.ModelName + " " + dev.ModelNumber),
		RawJSON: mustMarshalJSON(map[string]any{
			"manufacturer":     dev.Manufacturer,
			"model_name":       dev.ModelName,
			"model_number":     dev.ModelNumber,
			"firmware_version": dev.FirmwareVersion,
			"friendly_name":    dev.FriendlyName,
			"device_type":      dev.DeviceType,
			"udn":              dev.UDN,
			"server":           server,
		}),
	}

	banner := strings.TrimSpace("Belkin WeMo " + dev.ModelName + " " + dev.FirmwareVersion)

	return &Result{
		Target:      target,
		Protocol:    productWeMo,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// looksLikeWeMo skips full XML parsing for ports that just happen to be
// open with unrelated services on them.
func looksLikeWeMo(body []byte, server string) bool {
	lowered := strings.ToLower(string(body))
	if strings.Contains(lowered, wemoVendorHint) || strings.Contains(lowered, "wemo") {
		return true
	}

	return strings.Contains(strings.ToLower(server), wemoVendorHint)
}

// wemoDevice mirrors the WeMo subset of the UPnP <device> element. WeMo
// firmware historically emits `<firmwareVersion>` with the vendor strain
// embedded ("WeMo_WW_2.00.11451.PVT-OWRT-Insight") so we capture it raw.
type wemoDevice struct {
	DeviceType      string `xml:"deviceType"`
	FriendlyName    string `xml:"friendlyName"`
	Manufacturer    string `xml:"manufacturer"`
	ModelName       string `xml:"modelName"`
	ModelNumber     string `xml:"modelNumber"`
	FirmwareVersion string `xml:"firmwareVersion"`
	UDN             string `xml:"UDN"`
}

type wemoRoot struct {
	XMLName xml.Name   `xml:"root"`
	Device  wemoDevice `xml:"device"`
}

func parseWeMoSetup(body []byte) (wemoDevice, error) {
	var root wemoRoot

	if err := xml.Unmarshal(body, &root); err != nil {
		return wemoDevice{}, err
	}

	if root.Device.Manufacturer == "" && root.Device.ModelName == "" {
		return wemoDevice{}, errors.New("wemo: empty device block")
	}

	return root.Device, nil
}
