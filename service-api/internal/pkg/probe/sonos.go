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
	productSonos    = "sonos"
	sonosDeviceXML  = "/xml/device_description.xml"
	sonosBodyLimit  = 256 * 1024
	sonosVendorHint = "sonos"
)

func init() {
	// Sonos Play:N, Beam, Arc, Era, Roam, Move and One series all expose
	// the UPnP device description on TCP 1400.
	Register(probeSonos, 1400)
}

// probeSonos fetches the Sonos UPnP device description XML at
// /xml/device_description.xml. The document is a standard UPnP 1.0
// `<root><device>…</device></root>` envelope that carries manufacturer,
// modelName, modelNumber and softwareVersion fields. Sonos devices have
// shipped this endpoint unauthenticated since the very first generation.
//
// Mapping into FingerprintResult:
//
//	Product = "sonos"
//	Version = device.softwareVersion
//	Edition = device.modelName (+ modelNumber when present)
func probeSonos(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("http://%s%s", addr, sonosDeviceXML)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build Sonos description request: %w", err)
	}

	req.Header.Set("User-Agent", "UltraViolet/probe")

	client := &http.Client{Timeout: s.cfg.Timeout, Transport: s.httpTransport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't fetch Sonos description: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	limit := int64(s.cfg.MaxBody)
	if limit <= 0 || limit > sonosBodyLimit {
		limit = sonosBodyLimit
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("can't read Sonos description body: %w", err)
	}

	server := resp.Header.Get("Server")

	if resp.StatusCode/100 != 2 || !looksLikeSonos(body, server) {
		return &Result{Target: target, Protocol: protocolHTTP, Banner: server}, nil
	}

	dev, err := parseSonosDescription(body)
	if err != nil {
		return &Result{Target: target, Protocol: productSonos, Banner: server}, nil
	}

	fp := &FingerprintResult{
		Product: productSonos,
		Version: dev.SoftwareVersion,
		Edition: strings.TrimSpace(dev.ModelName + " " + dev.ModelNumber),
		RawJSON: mustMarshalJSON(map[string]any{
			"manufacturer":     dev.Manufacturer,
			"model_name":       dev.ModelName,
			"model_number":     dev.ModelNumber,
			"software_version": dev.SoftwareVersion,
			"hardware_version": dev.HardwareVersion,
			"udn":              dev.UDN,
			"server":           server,
		}),
	}

	banner := strings.TrimSpace("Sonos " + dev.ModelName + " " + dev.SoftwareVersion)

	return &Result{
		Target:      target,
		Protocol:    productSonos,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// looksLikeSonos performs a cheap fast-path check before XML parsing — the
// vast majority of port-1400 services either answer with a Sonos Server
// header or include the vendor name in the XML body.
func looksLikeSonos(body []byte, server string) bool {
	if strings.Contains(strings.ToLower(server), sonosVendorHint) {
		return true
	}

	return strings.Contains(strings.ToLower(string(body)), sonosVendorHint)
}

// sonosDevice mirrors the subset of fields we care about inside the
// `<device>` element of a UPnP description document.
type sonosDevice struct {
	Manufacturer    string `xml:"manufacturer"`
	ModelName       string `xml:"modelName"`
	ModelNumber     string `xml:"modelNumber"`
	SoftwareVersion string `xml:"softwareVersion"`
	HardwareVersion string `xml:"hardwareVersion"`
	UDN             string `xml:"UDN"`
}

type sonosRoot struct {
	XMLName xml.Name    `xml:"root"`
	Device  sonosDevice `xml:"device"`
}

// parseSonosDescription parses the UPnP root document and returns the
// inner <device> block. The Sonos firmware emits self-contained XML, so
// the top-level <root> always carries the device we want.
func parseSonosDescription(body []byte) (sonosDevice, error) {
	var root sonosRoot

	if err := xml.Unmarshal(body, &root); err != nil {
		return sonosDevice{}, err
	}

	if root.Device.Manufacturer == "" && root.Device.ModelName == "" {
		return sonosDevice{}, errors.New("sonos: empty device block")
	}

	return root.Device, nil
}
