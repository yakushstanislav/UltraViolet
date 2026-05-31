package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const productUPnP = "upnp"

func init() {
	// 10243 — Windows UPnP Device Host (HTTPS device description).
	// 1900  — SSDP over TCP on some embedded / Windows stacks.
	Register(probeUPnP, 10243, 1900)
}

func probeUPnP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	if target.Port == 1900 {
		return probeSSDPTCP(ctx, s, target)
	}

	return probeUPnPDeviceDescription(ctx, s, target)
}

func probeUPnPDeviceDescription(ctx context.Context, s *Stack, target Target) (*Result, error) {
	paths := []string{
		"/DeviceDescription.xml",
		"/ssdp/device-desc.xml",
		"/description.xml",
		"/xml/device_description.xml",
	}

	schemes := []string{"https", "http"}

	for _, scheme := range schemes {
		for _, path := range paths {
			result, ok := fetchUPnPDescription(ctx, s, target, scheme, path)
			if ok {
				return result, nil
			}
		}
	}

	return &Result{Target: target, Protocol: protocolTCP}, nil
}

func fetchUPnPDescription(
	ctx context.Context,
	s *Stack,
	target Target,
	scheme, path string,
) (*Result, bool) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	url := fmt.Sprintf("%s://%s%s", scheme, addr, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}

	req.Header.Set("User-Agent", "UltraViolet/probe")

	transport := s.httpTransport
	if scheme == "https" {
		transport = &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // scanner probes arbitrary hosts
		}
	}

	client := &http.Client{
		Timeout:   s.probeTimeout(ctx),
		Transport: transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || resp.StatusCode/100 != 2 {
		return nil, false
	}

	dev, err := parseUPnPDevice(body)
	if err != nil {
		return nil, false
	}

	banner := strings.TrimSpace(dev.Manufacturer + " " + dev.ModelName)
	if banner == "" {
		banner = "UPnP device"
	}

	fp := &FingerprintResult{
		Product: productUPnP,
		Version: strings.TrimSpace(dev.FirmwareVersion),
		Edition: strings.TrimSpace(dev.ModelName),
		RawJSON: mustMarshalJSON(map[string]any{
			"path":             path,
			"scheme":           scheme,
			"manufacturer":     dev.Manufacturer,
			"model_name":       dev.ModelName,
			"model_number":     dev.ModelNumber,
			"firmware_version": dev.FirmwareVersion,
			"friendly_name":    dev.FriendlyName,
		}),
	}

	protocol := protocolHTTP
	if scheme == "https" {
		protocol = protocolHTTPS
	}

	return &Result{
		Target:      target,
		Protocol:    protocol,
		Banner:      banner,
		Fingerprint: fp,
	}, true
}

type upnpDeviceFields struct {
	Manufacturer    string `xml:"manufacturer"`
	ModelName       string `xml:"modelName"`
	ModelNumber     string `xml:"modelNumber"`
	FirmwareVersion string `xml:"firmwareVersion"`
	FriendlyName    string `xml:"friendlyName"`
}

func parseUPnPDevice(body []byte) (*upnpDeviceFields, error) {
	var root struct {
		Device upnpDeviceFields `xml:"device"`
	}

	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, err
	}

	if root.Device.Manufacturer == "" && root.Device.ModelName == "" {
		return nil, errors.New("upnp: empty device block")
	}

	return &root.Device, nil
}

func probeSSDPTCP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial SSDP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	request := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		"MAN: \"ssdp:discover\"",
		"MX: 2",
		"ST: upnp:rootdevice",
		"USER-AGENT: UltraViolet/1.0",
		"",
		"",
	}, "\r\n")

	if _, writeErr := io.WriteString(conn, request); writeErr != nil {
		return nil, fmt.Errorf("can't send SSDP M-SEARCH: %w", writeErr)
	}

	reader := bufio.NewReader(conn)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	text := readUntilSSDPTimeout(reader, 4096)

	if !strings.Contains(strings.ToUpper(text), "HTTP/1.") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: firstLine(text)}, nil
	}

	server := ""
	usn := ""

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}

		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			server = strings.TrimSpace(line[len("server:"):])
		}

		if strings.HasPrefix(lower, "usn:") {
			usn = strings.TrimSpace(line[len("usn:"):])
		}
	}

	banner := server
	if banner == "" {
		banner = firstLine(text)
	}

	fp := &FingerprintResult{
		Product: productUPnP,
		RawJSON: mustMarshalJSON(map[string]any{
			"server": server,
			"usn":    usn,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productUPnP,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

func readUntilSSDPTimeout(reader *bufio.Reader, limit int) string {
	var b strings.Builder

	for b.Len() < limit {
		line, err := reader.ReadString('\n')
		if line != "" {
			b.WriteString(line)
		}

		if err != nil {
			break
		}
	}

	return b.String()
}
