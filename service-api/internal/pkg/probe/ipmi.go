package probe

import (
	"context"
	"encoding/hex"
	"fmt"
)

func init() {
	RegisterUDP(probeIPMI, 623)
}

// probeIPMI sends an RMCP+ Get Channel Authentication Capabilities request
// to expose IPMI version and authentication flags.
func probeIPMI(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial IPMI target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	request := ipmiGetAuthCapabilities()

	if _, writeErr := conn.Write(request); writeErr != nil {
		return nil, fmt.Errorf("can't write IPMI request: %w", writeErr)
	}

	resp := make([]byte, 1024)

	n, err := conn.Read(resp)
	if err != nil || n < 24 {
		return nil, fmt.Errorf("can't read IPMI response: %w", err)
	}

	channel := byte(0)
	ipmi15 := false
	ipmi20 := false

	if n >= 24 {
		channel = resp[16]
		authCaps := resp[17]
		ipmi15 = authCaps&0x80 == 0
		ipmi20 = authCaps&0x80 != 0
	}

	authRequired := true

	return &Result{
		Target:   target,
		Protocol: "ipmi",
		Fingerprint: &FingerprintResult{
			Product:      "ipmi",
			Version:      ipmiVersionLabel(ipmi15, ipmi20),
			AuthRequired: &authRequired,
			RawJSON: mustMarshalJSON(map[string]any{
				"channel":    channel,
				"ipmi_1_5":   ipmi15,
				"ipmi_2_0":   ipmi20,
				"raw_hex":    hex.EncodeToString(resp[:n]),
				"bytes_read": n,
			}),
		},
	}, nil
}

func ipmiVersionLabel(ipmi15, ipmi20 bool) string {
	switch {
	case ipmi20 && ipmi15:
		return "1.5+2.0"
	case ipmi20:
		return "2.0"
	case ipmi15:
		return "1.5"
	}

	return ""
}

// ipmiGetAuthCapabilities builds an RMCP+ Get Channel Authentication
// Capabilities request (channel 0x0e = current, user privilege).
func ipmiGetAuthCapabilities() []byte {
	return []byte{
		0x06, 0x00, 0xff, 0x07,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x18, 0xc8,
		0x81, 0x00, 0x38,
		0x8e, 0x04,
		0x31,
	}
}
