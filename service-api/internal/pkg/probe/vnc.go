package probe

import (
	"context"
	"fmt"
	"strings"
)

func init() {
	Register(probeVNC, 5900, 5901, 5902, 5903)
}

// probeVNC reads the RFB ProtocolVersion message ("RFB 003.008\n"),
// responds with the same version, and reads the security types byte to
// detect None auth.
func probeVNC(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial VNC target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	buf := make([]byte, 12)

	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil, fmt.Errorf("can't read VNC ProtocolVersion: %w", err)
	}

	version := strings.TrimRight(string(buf[:12]), "\r\n")

	if !strings.HasPrefix(version, "RFB ") {
		return &Result{
			Target:   target,
			Protocol: protocolTCP,
			Banner:   version,
		}, nil
	}

	if _, err := conn.Write([]byte(version + "\n")); err != nil {
		return rfbResult(target, version, nil), nil
	}

	headerBuf := make([]byte, 1)

	if _, err := conn.Read(headerBuf); err != nil {
		return rfbResult(target, version, nil), nil
	}

	count := int(headerBuf[0])

	if count == 0 {
		return rfbResult(target, version, []string{"failure"}), nil
	}

	types := make([]byte, count)
	if _, err := conn.Read(types); err != nil {
		return rfbResult(target, version, []string{"unknown"}), nil
	}

	names := make([]string, 0, count)

	noneAvailable := false

	for _, t := range types {
		name := vncSecurityName(t)
		names = append(names, name)

		if t == 1 {
			noneAvailable = true
		}
	}

	return rfbResult(target, version, names, noneAvailable), nil
}

func rfbResult(target Target, version string, securityTypes []string, noneFlag ...bool) *Result {
	noneAvailable := false
	if len(noneFlag) > 0 {
		noneAvailable = noneFlag[0]
	}

	authRequired := !noneAvailable

	return &Result{
		Target:   target,
		Protocol: "vnc",
		Banner:   version,
		Fingerprint: &FingerprintResult{
			Product:      "vnc",
			Version:      strings.TrimPrefix(version, "RFB "),
			AuthRequired: &authRequired,
			Anonymous:    noneAvailable,
			RawJSON: mustMarshalJSON(map[string]any{
				"protocol_version": version,
				"security_types":   securityTypes,
				"none_available":   noneAvailable,
			}),
		},
	}
}

// vncSecurityName maps the RFB security-type byte to a printable name.
func vncSecurityName(code byte) string {
	switch code {
	case 1:
		return "None"
	case 2:
		return "VNC"
	case 5:
		return "RA2"
	case 6:
		return "RA2ne"
	case 16:
		return "Tight"
	case 17:
		return "Ultra"
	case 18:
		return "TLS"
	case 19:
		return "VeNCrypt"
	case 20:
		return "SASL"
	case 21:
		return "MD5Hash"
	case 22:
		return "XVP"
	case 30:
		return "Apple"
	}

	return "code_" + telnetByteHex(code)
}
