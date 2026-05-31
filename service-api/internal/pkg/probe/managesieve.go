package probe

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	productManageSieve = "managesieve"
	productCiscoSCCP   = "cisco_skinny"
)

var managesieveImplementationRE = regexp.MustCompile(`(?i)"?IMPLEMENTATION"?\s+"?([^"\r\n]+)"?`)

func init() {
	// 2000 — Cyrus timsieved / ManageSieve (RFC 5804) and Cisco SCCP (Skinny).
	Register(probePort2000, 2000)
}

// probePort2000 detects ManageSieve text banners and Cisco Skinny (SCCP) binary
// frames on the shared IANA port 2000.
func probePort2000(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial port 2000 target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	buf := make([]byte, 2048)

	n, _ := conn.Read(buf)
	if n == 0 {
		if _, writeErr := io.WriteString(conn, "CAPABILITY\r\n"); writeErr != nil {
			return &Result{Target: target, Protocol: protocolTCP}, nil
		}

		reader := bufio.NewReader(conn)

		text := readManageSieveText(reader, 2048)
		if fp := fingerprintManageSieve(text); fp != nil {
			return &Result{
				Target:      target,
				Protocol:    productManageSieve,
				Banner:      firstLine(text),
				Fingerprint: fp,
			}, nil
		}

		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	raw := buf[:n]

	if fp := fingerprintManageSieve(string(raw)); fp != nil {
		return &Result{
			Target:      target,
			Protocol:    productManageSieve,
			Banner:      firstLine(string(raw)),
			Fingerprint: fp,
		}, nil
	}

	if fp := fingerprintCiscoSCCP(raw); fp != nil {
		return &Result{
			Target:      target,
			Protocol:    productCiscoSCCP,
			Banner:      "Cisco Skinny",
			Fingerprint: fp,
		}, nil
	}

	if _, writeErr := io.WriteString(conn, "CAPABILITY\r\n"); writeErr == nil {
		reader := bufio.NewReader(io.MultiReader(
			strings.NewReader(string(raw)),
			conn,
		))

		text := readManageSieveText(reader, 2048)
		if fp := fingerprintManageSieve(text); fp != nil {
			return &Result{
				Target:      target,
				Protocol:    productManageSieve,
				Banner:      firstLine(text),
				Fingerprint: fp,
			}, nil
		}
	}

	return &Result{Target: target, Protocol: protocolTCP, Banner: string(raw)}, nil
}

func readManageSieveText(reader *bufio.Reader, limit int) string {
	var b strings.Builder

	for b.Len() < limit {
		line, err := reader.ReadString('\n')
		if line != "" {
			b.WriteString(line)
		}

		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upper, "OK") {
			break
		}

		if err != nil {
			break
		}
	}

	return b.String()
}

func fingerprintManageSieve(text string) *FingerprintResult {
	if text == "" {
		return nil
	}

	upper := strings.ToUpper(text)
	if !strings.Contains(upper, "IMPLEMENTATION") &&
		!strings.Contains(upper, "\"SASL\"") &&
		!strings.Contains(upper, "\"SIEVE\"") &&
		!strings.Contains(upper, "MANAGESIEVE") {
		return nil
	}

	version := ""
	edition := ""

	if m := managesieveImplementationRE.FindStringSubmatch(text); len(m) >= 2 {
		edition = strings.TrimSpace(m[1])
		if idx := strings.Index(strings.ToLower(edition), "v"); idx > 0 {
			candidate := strings.TrimSpace(edition[idx+1:])
			if fields := strings.Fields(candidate); len(fields) > 0 {
				version = fields[0]
			}
		}
	}

	product := productManageSieve
	if strings.Contains(strings.ToLower(edition), "cyrus") {
		product = "cyrus"
	}

	return &FingerprintResult{
		Product: product,
		Version: version,
		Edition: edition,
		RawJSON: mustMarshalJSON(map[string]any{
			"implementation": edition,
		}),
	}
}

// fingerprintCiscoSCCP checks for a Skinny/SCCP frame: 8-byte header where
// bytes 4–7 are version 0 and message type is a small integer.
func fingerprintCiscoSCCP(raw []byte) *FingerprintResult {
	if len(raw) < 12 {
		return nil
	}

	length := binary.BigEndian.Uint32(raw[0:4])
	if length < 8 || length > 4096 {
		return nil
	}

	version := binary.BigEndian.Uint32(raw[4:8])
	if version != 0 {
		return nil
	}

	msgType := binary.BigEndian.Uint32(raw[8:12])
	if msgType > 0x200 {
		return nil
	}

	return &FingerprintResult{
		Product: productCiscoSCCP,
		RawJSON: mustMarshalJSON(map[string]any{
			"length":   length,
			"msg_type": msgType,
		}),
	}
}
