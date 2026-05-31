package probe

import (
	"context"
	"fmt"
	"io"
	"strings"
)

const productNetBIOS = "netbios_ssn"

func init() {
	Register(probeNetBIOS, 139)
}

// probeNetBIOS sends a NetBIOS session request to the *SMBSERVER name and
// treats a positive session response (0x82) as proof of the service.
func probeNetBIOS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial NetBIOS target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	pkt := buildNetBIOSSessionRequest("*SMBSERVER", "ULTRAVIOLET")

	if _, writeErr := conn.Write(pkt); writeErr != nil {
		return nil, fmt.Errorf("can't send NetBIOS session request: %w", writeErr)
	}

	header := make([]byte, 4)

	n, err := io.ReadFull(conn, header)
	if err != nil || n < 4 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	if header[0] != 0x82 {
		return &Result{Target: target, Protocol: protocolTCP, Banner: fmt.Sprintf("%#v", header)}, nil
	}

	fp := &FingerprintResult{
		Product: productNetBIOS,
		RawJSON: mustMarshalJSON(map[string]any{
			"response_type": header[0],
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productNetBIOS,
		Banner:      "NetBIOS session accepted",
		Fingerprint: fp,
	}, nil
}

func buildNetBIOSSessionRequest(called, calling string) []byte {
	calledEnc := encodeNetBIOSName(called)
	callingEnc := encodeNetBIOSName(calling)

	payload := make([]byte, 0, len(calledEnc)+len(callingEnc))
	payload = append(payload, calledEnc...)
	payload = append(payload, callingEnc...)

	out := make([]byte, 0, 4+len(payload))
	out = append(out, 0x81, 0x00)
	out = append(out, byte(len(payload)>>8), byte(len(payload)))
	out = append(out, payload...)

	return out
}

func encodeNetBIOSName(name string) []byte {
	name = name + strings.Repeat(" ", 16)
	if len(name) > 16 {
		name = name[:16]
	}

	encoded := make([]byte, 0, 34)
	encoded = append(encoded, byte(len(name)*2))

	for i := range 16 {
		ch := name[i]
		if ch < ' ' {
			ch = ' '
		}

		encoded = append(encoded, 'A'+(ch>>4))
		encoded = append(encoded, 'A'+(ch&0x0f))
	}

	return encoded
}
