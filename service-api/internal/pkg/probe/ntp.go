package probe

import (
	"context"
	"fmt"
)

func init() {
	RegisterUDP(probeNTP, 123)
}

// probeNTP sends an NTP v4 client packet (mode 3) and reports the server
// stratum, version, reference ID and precision from the response.
func probeNTP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial NTP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	request := make([]byte, 48)
	request[0] = 0x1b

	if _, writeErr := conn.Write(request); writeErr != nil {
		return nil, fmt.Errorf("can't write NTP request: %w", writeErr)
	}

	resp := make([]byte, 48)

	n, err := conn.Read(resp)
	if err != nil || n < 48 {
		return nil, fmt.Errorf("can't read NTP response: %w", err)
	}

	li := resp[0] >> 6
	version := (resp[0] >> 3) & 0x07
	mode := resp[0] & 0x07
	stratum := resp[1]
	poll := int8(resp[2])
	precision := int8(resp[3])
	refID := resp[12:16]

	return &Result{
		Target:   target,
		Protocol: "ntp",
		Fingerprint: &FingerprintResult{
			Product: "ntp",
			Version: fmt.Sprintf("v%d", version),
			RawJSON: mustMarshalJSON(map[string]any{
				"li":        li,
				"version":   version,
				"mode":      mode,
				"stratum":   stratum,
				"poll":      poll,
				"precision": precision,
				"ref_id":    fmt.Sprintf("%d.%d.%d.%d", refID[0], refID[1], refID[2], refID[3]),
			}),
		},
	}, nil
}
