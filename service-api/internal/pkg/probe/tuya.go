package probe

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const productTuya = "tuya_device"

// tuyaMagicPrefix is the 4-byte preamble every Tuya LAN-protocol frame
// starts with (big-endian 0x000055AA). The matching suffix is 0x0000AA55.
var (
	tuyaMagicPrefix = [4]byte{0x00, 0x00, 0x55, 0xAA}
	tuyaMagicSuffix = [4]byte{0x00, 0x00, 0xAA, 0x55}
)

func init() {
	// Tuya v3.x devices (genuine Tuya, plus Smart Life, BlitzWolf,
	// Treatlife, Gosund, Teckin, Geeni and ~40 other re-brands) listen
	// on TCP 6668 for the LAN control protocol.
	Register(probeTuya, 6668)
}

// probeTuya sends a DP_QUERY_NEW-style discovery frame on the Tuya LAN
// protocol port. Even when the device only accepts encrypted local-key
// commands, it answers any well-formed envelope with another framed
// response whose 0x000055AA prefix identifies the Tuya stack without
// needing the local key.
//
// Wire format (Tuya LAN, v3.3+):
//
//	prefix       uint32 BE = 0x000055AA
//	sequence     uint32 BE
//	command      uint32 BE   (0x09 HEART_BEAT, 0x0A DP_QUERY,
//	                          0x0D DP_QUERY_NEW, 0xFF discovery)
//	payload_len  uint32 BE
//	payload      []byte
//	crc32        uint32 BE   (over prefix..end-of-payload)
//	suffix       uint32 BE = 0x0000AA55
//
// We don't compute the CRC — Tuya devices reply with an error frame for
// invalid CRCs, and that error frame is itself a Tuya envelope (still
// starts with the magic prefix), which is all we need to flag the host.
func probeTuya(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	req := make([]byte, 0, 24)
	req = append(req, tuyaMagicPrefix[:]...)
	req = appendUint32BE(req, 1)          // sequence
	req = appendUint32BE(req, 0x000000FF) // command (discovery)
	req = appendUint32BE(req, 0)          // payload length
	req = append(req, tuyaMagicSuffix[:]...)

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 1024)

	n, _ := conn.Read(buf)
	if n < 4 {
		return nil, errors.New("tuya: short reply")
	}

	if buf[0] != tuyaMagicPrefix[0] || buf[1] != tuyaMagicPrefix[1] ||
		buf[2] != tuyaMagicPrefix[2] || buf[3] != tuyaMagicPrefix[3] {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	command := uint32(0)

	if n >= 16 {
		command = binary.BigEndian.Uint32(buf[8:12])
	}

	fp := &FingerprintResult{
		Product: productTuya,
		RawJSON: mustMarshalJSON(map[string]any{
			"reply_hex":  hex.EncodeToString(buf[:n]),
			"reply_cmd":  command,
			"reply_size": n,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productTuya,
		Banner:      "Tuya LAN protocol",
		Fingerprint: fp,
	}, nil
}

// appendUint32BE appends a big-endian uint32 to buf and returns the
// extended slice. Used so we don't import "encoding/binary" twice — it's
// already pulled in for the response parser above, but the helper keeps
// the request builder readable.
func appendUint32BE(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
