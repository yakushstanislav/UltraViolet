package probe

import (
	"context"
	"fmt"
)

func init() {
	Register(probeRDP, 3389)
}

// probeRDP performs the X.224 Connection Request with a RDP Negotiation
// Request and parses the NEG_RSP / NEG_FAILURE response to expose the set
// of supported protocols (TLS, CredSSP, RDSTLS).
func probeRDP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial RDP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	request := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e,
		0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01,
		0x00,
		0x08, 0x00,
		0x0b, 0x00, 0x00, 0x00,
	}

	if _, writeErr := conn.Write(request); writeErr != nil {
		return nil, fmt.Errorf("can't write RDP request: %w", writeErr)
	}

	resp := make([]byte, 19)

	n, err := conn.Read(resp)
	if err != nil || n < 11 {
		return nil, fmt.Errorf("can't read RDP response: %w", err)
	}

	if resp[0] != 0x03 {
		return &Result{Target: target, Protocol: "rdp"}, nil
	}

	negType := byte(0)
	flags := byte(0)
	negData := uint32(0)

	if n >= 19 {
		negType = resp[11]
		flags = resp[12]
		negData = uint32(resp[15]) | uint32(resp[16])<<8 | uint32(resp[17])<<16 | uint32(resp[18])<<24
	}

	protocols := []string{}

	if negType == 0x02 {
		if negData&0x00000001 != 0 {
			protocols = append(protocols, "TLS")
		}

		if negData&0x00000002 != 0 {
			protocols = append(protocols, "CredSSP")
		}

		if negData&0x00000004 != 0 {
			protocols = append(protocols, "RDSTLS")
		}

		if negData&0x00000008 != 0 {
			protocols = append(protocols, "EarlyUserAuth")
		}
	}

	nlaRequired := false

	for _, p := range protocols {
		if p == "CredSSP" {
			nlaRequired = true

			break
		}
	}

	failureCode := uint32(0)
	if negType == 0x03 {
		failureCode = negData
	}

	return &Result{
		Target:   target,
		Protocol: "rdp",
		Fingerprint: &FingerprintResult{
			Product:      "rdp",
			AuthRequired: boolPtr(nlaRequired),
			TLSRequired:  boolPtr(len(protocols) > 0),
			RawJSON: mustMarshalJSON(map[string]any{
				"negotiation_type":  negType,
				"flags":             flags,
				"selected_protocol": negData,
				"protocols":         protocols,
				"failure_code":      failureCode,
				"nla_required":      nlaRequired,
			}),
		},
	}, nil
}
