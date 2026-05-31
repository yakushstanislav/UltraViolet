package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const productMELSEC = "mitsubishi_melsec"

func init() {
	// MELSEC iQ-R / iQ-F / Q series — TCP 5006 (binary frame) and 5007
	// (ASCII frame). Both speak SLMP; we issue the request in 3E binary,
	// which is what every supported CPU answers regardless of the listen
	// port preference.
	Register(probeMELSEC, 5006, 5007)
}

// probeMELSEC sends an SLMP "Read CPU Model Name" request (command
// 0x0101 / subcommand 0x0000) and parses the 16-byte ASCII model returned
// in the response data field.
//
// Frame layout (SLMP 3E binary, CC-Link Partner Association spec):
//
//	subheader     uint16 LE = 0x0050  (request)
//	network       uint8     = 0x00    (local network)
//	pc            uint8     = 0xFF    (local PC)
//	module_io     uint16 LE = 0x03FF  (CPU module)
//	multidrop     uint8     = 0x00
//	req_length    uint16 LE = 0x0006  (timer + command + subcommand)
//	monitor_timer uint16 LE = 0x0000
//	command       uint16 LE = 0x0101
//	subcommand    uint16 LE = 0x0000
//
// Response layout: same prefix with subheader 0x00D0, followed by
// end_code uint16 LE (0 = success) and the 16-byte CPU model ASCII.
// Mitsubishi documents the CPU model as space-padded so we trim.
func probeMELSEC(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	req := []byte{
		0x50, 0x00, // subheader
		0x00,       // network
		0xFF,       // pc
		0xFF, 0x03, // module_io
		0x00,       // multidrop
		0x06, 0x00, // req_length
		0x00, 0x00, // monitor_timer
		0x01, 0x01, // command
		0x00, 0x00, // subcommand
	}

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 64)

	n, err := io.ReadAtLeast(conn, buf, 11)
	if err != nil || n < 11 {
		return nil, errors.New("melsec: short SLMP reply")
	}

	subheader := binary.LittleEndian.Uint16(buf[0:2])
	if subheader != 0x00D0 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	respLen := int(binary.LittleEndian.Uint16(buf[9:11]))
	if respLen < 18 || n < 11+respLen {
		_, _ = io.ReadAtLeast(conn, buf[n:], 11+respLen-n)
	}

	endCode := binary.LittleEndian.Uint16(buf[11:13])
	if endCode != 0 {
		return &Result{
			Target:   target,
			Protocol: productMELSEC,
			Banner:   "Mitsubishi SLMP",
			Fingerprint: &FingerprintResult{
				Product: productMELSEC,
				RawJSON: mustMarshalJSON(map[string]any{"end_code": endCode}),
			},
		}, nil
	}

	if n < 11+2+16 {
		return &Result{Target: target, Protocol: productMELSEC, Banner: "Mitsubishi SLMP"}, nil
	}

	model := strings.TrimSpace(strings.TrimRight(string(buf[13:29]), "\x00 "))

	fp := &FingerprintResult{
		Product: productMELSEC,
		Edition: model,
		RawJSON: mustMarshalJSON(map[string]any{
			"cpu_model": model,
			"end_code":  endCode,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productMELSEC,
		Banner:      "Mitsubishi MELSEC " + model,
		Fingerprint: fp,
	}, nil
}
