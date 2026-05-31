package probe

import (
	"context"
	"io"
)

const productX11 = "x11"

func init() {
	// X11 TCP displays :0..:5 map to ports 6000..6005 (6000 + display).
	Register(probeX11, 6000, 6001, 6002, 6003, 6004, 6005)
}

// probeX11 sends a minimal X11 connection setup request (little-endian
// 'l' byte order, protocol 11.0, no auth). A real Xorg/Xvfb/xpra server
// replies with a setup reply whose first byte is 0 (success), 1
// (authenticate), or 2 (failure) — all three prove an X server is
// listening.
func probeX11(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	req := buildX11SetupRequest()

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 32)

	n, err := io.ReadAtLeast(conn, buf, 8)
	if err != nil || n < 8 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	status := buf[0]

	if status > 2 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	fp := &FingerprintResult{
		Product: productX11,
		RawJSON: mustMarshalJSON(map[string]any{
			"setup_status": status,
			"display_port": target.Port,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productX11,
		Banner:      "X11 display",
		Fingerprint: fp,
	}, nil
}

// buildX11SetupRequest builds a 12-byte unauthenticated X11 connection
// setup: byte-order 'l' (LSBFirst), major 11, minor 0, zero-length auth.
func buildX11SetupRequest() []byte {
	return []byte{
		0x6c, // 'l' LSBFirst
		0x00,
		0x0b, 0x00, // major 11
		0x00, 0x00, // minor 0
		0x00, 0x00, // auth name len
		0x00, 0x00, // auth data len
		0x00, 0x00, // unused
	}
}
