package probe

import (
	"context"
	"encoding/binary"
	"strings"
	"time"
)

const productUniversalRobots = "universal_robots"

func init() {
	// 30001 — UR primary client interface. 30002 (secondary) and
	// 30003 (real-time) speak the same protocol but at different
	// rates; 30004 (RTDE) is binary. Registering just 30001 covers
	// the canonical detection path used by the URCap installer.
	Register(probeUniversalRobots, 30001)
}

// probeUniversalRobots reads the URControl banner stream that the
// primary client interface pushes on connect. The very first packet
// carries a 4-byte big-endian length prefix and a message header that
// includes the controller version string in ASCII.
func probeUniversalRobots(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(s.probeTimeout(ctx)))

	buf := make([]byte, 8192)

	n, _ := conn.Read(buf)
	if n < 4 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	raw := extractURMessageText(buf[:n])
	lower := strings.ToLower(raw)

	if !strings.Contains(lower, "urcontrol") &&
		!strings.Contains(lower, "universal robots") &&
		!strings.Contains(lower, "polyscope") &&
		!strings.Contains(lower, "ursoftware") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: firstLine(raw)}, nil
	}

	version := extractURVersion(raw)

	fp := &FingerprintResult{
		Product: productUniversalRobots,
		Version: version,
		RawJSON: mustMarshalJSON(map[string]any{
			"banner":  firstLine(raw),
			"version": version,
		}),
	}

	banner := "Universal Robots URControl"
	if version != "" {
		banner = banner + " " + version
	}

	return &Result{
		Target:      target,
		Protocol:    productUniversalRobots,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// extractURMessageText walks length-prefixed UR messages in the buffer and
// returns the concatenated ASCII payloads for marker scanning.
func extractURMessageText(buf []byte) string {
	var parts []string

	offset := 0

	for offset+4 <= len(buf) {
		msgLen := int(binary.BigEndian.Uint32(buf[offset : offset+4]))
		if msgLen <= 0 || offset+4+msgLen > len(buf) {
			break
		}

		payload := buf[offset+4 : offset+4+msgLen]
		if len(payload) > 0 {
			parts = append(parts, string(payload))
		}

		offset += 4 + msgLen
	}

	if len(parts) > 0 {
		return strings.Join(parts, "\n")
	}

	return string(buf)
}

// extractURVersion scans the URControl banner for a "URControl version
// 5.11.0" / "PolyScope 5.16.0.108917" / "URSoftware 5.12.0" fragment.
func extractURVersion(s string) string {
	for _, marker := range []string{"URControl version ", "URControl ", "PolyScope ", "URSoftware ", "UR-Control "} {
		idx := strings.Index(s, marker)
		if idx < 0 {
			continue
		}

		tail := s[idx+len(marker):]

		end := len(tail)

		for i, c := range tail {
			if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
				end = i

				break
			}
		}

		if end > 0 && tail[0] >= '0' && tail[0] <= '9' {
			return tail[:end]
		}
	}

	return ""
}
