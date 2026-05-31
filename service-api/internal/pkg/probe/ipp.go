package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
)

const (
	productCUPS = "cups"
	productIPP  = "ipp"
)

// cupsVersionRE pulls "CUPS/2.4.1" from a Server response header.
var cupsVersionRE = regexp.MustCompile(`(?i)CUPS/([\w.\-]+)`)

func init() {
	Register(probeIPP, 631)
}

// probeIPP issues an IPP "Get-Printer-Attributes" operation to enumerate
// the printer (or CUPS scheduler) at the target. Two payload sizes worth
// of value land in our fingerprint:
//
//   - the Server response header of the HTTP wrapping, which on CUPS-
//     based stacks (Linux, macOS, OpenWRT, embedded MFP firmware,
//     Synology, QNAP) always reads `CUPS/<version>`. That gives us the
//     CUPS version without parsing any IPP attribute.
//   - the IPP attribute group itself, which carries:
//   - printer-make-and-model
//   - printer-state
//   - cups-version (CUPS-specific extension attribute)
//
// CUPS RCEs disclosed in 2024-2025 (CVE-2024-47076 to CVE-2024-47177)
// hit the cups-browsed daemon over IPP, so an accurate CUPS version is
// the single most useful fingerprint a network probe can collect off a
// printer.
func probeIPP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	addr := net.JoinHostPort(target.IP.String(), "631")
	url := "http://" + addr + "/"

	body := buildIPPGetPrinterAttributes(url)

	timeout := s.probeTimeout(ctx)

	httpClient := &http.Client{
		Transport: s.httpTransport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/ipp")
	req.Header.Set("User-Agent", "UltraViolet/IPP")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	server := resp.Header.Get("Server")
	product := productIPP
	version := ""

	if match := cupsVersionRE.FindStringSubmatch(server); len(match) == 2 {
		product = productCUPS
		version = match[1]
	}

	attrs := parseIPPAttributes(respBody)

	if cupsVersion, ok := attrs["cups-version"]; ok {
		product = productCUPS
		version = cupsVersion
	}

	model := attrs["printer-make-and-model"]
	state := attrs["printer-state-reasons"]
	banner := strings.TrimSpace(model)

	if banner == "" {
		banner = server
	}

	fp := &FingerprintResult{
		Product: product,
		Version: version,
		Edition: model,
		RawJSON: mustMarshalJSON(map[string]any{
			"server":         server,
			"http_status":    resp.StatusCode,
			"model":          model,
			"state_reasons":  state,
			"attribute_keys": ippKeys(attrs),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    product,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// buildIPPGetPrinterAttributes builds a minimal IPP/2.0
// Get-Printer-Attributes request. The body shape:
//
//	02 00                         (version 2.0)
//	00 0B                         (operation-id: Get-Printer-Attributes)
//	00 00 00 01                   (request-id)
//	01                            (operation-attributes-tag)
//	47 00 12 attributes-charset      00 05 utf-8
//	48 00 1B attributes-natural-language 00 02 en
//	45 00 0B printer-uri          <printerURI>
//	03                            (end-of-attributes-tag)
func buildIPPGetPrinterAttributes(printerURI string) []byte {
	var buf bytes.Buffer

	buf.Write([]byte{0x02, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x01})

	writeIPPAttr(&buf, 0x47, "attributes-charset", "utf-8")
	writeIPPAttr(&buf, 0x48, "attributes-natural-language", "en")
	writeIPPAttr(&buf, 0x45, "printer-uri", printerURI)

	buf.WriteByte(0x03)

	return buf.Bytes()
}

func writeIPPAttr(buf *bytes.Buffer, tag byte, name, value string) {
	buf.WriteByte(tag)

	nameLen := make([]byte, 2)
	binary.BigEndian.PutUint16(nameLen, uint16(len(name)))
	buf.Write(nameLen)
	buf.WriteString(name)

	valueLen := make([]byte, 2)
	binary.BigEndian.PutUint16(valueLen, uint16(len(value)))
	buf.Write(valueLen)
	buf.WriteString(value)
}

// parseIPPAttributes walks the IPP response body and pulls a flat map of
// printable string attributes. It tolerates malformed groups: a single
// bad length byte stops the walk instead of crashing the probe.
func parseIPPAttributes(b []byte) map[string]string {
	out := map[string]string{}

	if len(b) < 9 {
		return out
	}

	i := 8

	currentName := ""

	for i < len(b) {
		tag := b[i]
		i++

		// Delimiter / group tags carry no payload.
		if tag < 0x10 {
			currentName = ""

			if tag == 0x03 {
				break
			}

			continue
		}

		if i+2 > len(b) {
			break
		}

		nameLen := int(binary.BigEndian.Uint16(b[i : i+2]))
		i += 2

		if i+nameLen > len(b) {
			break
		}

		name := string(b[i : i+nameLen])
		i += nameLen

		if i+2 > len(b) {
			break
		}

		valueLen := int(binary.BigEndian.Uint16(b[i : i+2]))
		i += 2

		if i+valueLen > len(b) {
			break
		}

		value := string(b[i : i+valueLen])
		i += valueLen

		if name == "" && currentName != "" {
			// Additional value for a multi-value attribute.
			out[currentName] = out[currentName] + ", " + value

			continue
		}

		currentName = name

		// Only retain printable text-style tags for the result map.
		switch tag {
		case 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
			0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
			0x41, 0x42, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49:
			out[name] = value
		}
	}

	return out
}

func ippKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))

	for k := range m {
		out = append(out, k)
	}

	return out
}
