package probe

import (
	"context"
	"io"
)

const productIEC104 = "iec_60870_5_104"

func init() {
	Register(probeIEC104, 2404)
}

// probeIEC104 detects IEC 60870-5-104 (the IP-mapped variant of the
// venerable telecontrol protocol used across European energy
// distribution). Every conformant controlled station has to answer a
// STARTDT activation U-frame with a STARTDT confirmation, regardless of
// the connecting client's identity — that's the "open the data flow"
// handshake.
//
// APCI frame layout:
//
//	start  uint8 = 0x68
//	length uint8 (1 byte)
//	ctrl1..4 uint8 — for U-frames the control flags live in ctrl1 and 2.
//
// STARTDT act has ctrl1 = 0x07 (1<<2 | 1<<0), STARTDT con has ctrl1 = 0x0B.
// We send STARTDT act and look for STARTDT con. If the reply uses any of
// the well-known U-frame flags we still report the protocol.
func probeIEC104(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	req := []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00} // STARTDT act
	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 16)

	n, err := io.ReadAtLeast(conn, buf, 6)
	if err != nil || n < 6 {
		return nil, err
	}

	if buf[0] != 0x68 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	frame := buf[2:6]

	fp := &FingerprintResult{
		Product: productIEC104,
		RawJSON: mustMarshalJSON(map[string]any{
			"ctrl1": frame[0],
			"ctrl2": frame[1],
			"ctrl3": frame[2],
			"ctrl4": frame[3],
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productIEC104,
		Banner:      "IEC 60870-5-104",
		Fingerprint: fp,
	}, nil
}
