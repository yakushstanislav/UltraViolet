package probe

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const productXiaomiMiIO = "xiaomi_miio_device"

// miioMagic is the 16-bit preamble all miIO frames start with. Combined
// with the fixed length field 0x0020 (32 bytes total) it uniquely
// identifies miIO discovery traffic — no other UDP/54321 service uses the
// same pair of constants.
const miioMagic uint16 = 0x2131

func init() {
	// Xiaomi Mi Home gateways, Aqara hubs, Mi Robot vacuums, Yeelight
	// bulbs (legacy firmwares), Mi Air Purifier and a wide range of
	// re-branded ChuangmiJia/Lumi/Roborock products all listen on
	// UDP 54321 for the miIO control protocol.
	RegisterUDP(probeXiaomiMiIO, 54321)
}

// probeXiaomiMiIO sends the canonical "Hello" packet that Xiaomi's miIO
// reference implementation uses to discover devices on the LAN. The
// packet is a fixed 32-byte preamble:
//
//	0x21 0x31           — magic
//	0x00 0x20           — total length (32)
//	0xFFFFFFFF          — unknown / reserved
//	0xFFFFFFFF          — device id placeholder
//	0x00000000          — timestamp placeholder
//	16 × 0x00           — MD5 checksum / token placeholder
//
// Every miIO firmware replies with another 32-byte envelope where the
// reserved field carries the device serial number and the timestamp
// slot returns the device clock. We surface both as fingerprint metadata
// so cvematch can route on the device id range when needed.
func probeXiaomiMiIO(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	req := make([]byte, 32)
	binary.BigEndian.PutUint16(req[0:2], miioMagic)
	binary.BigEndian.PutUint16(req[2:4], 0x0020)

	for i := 4; i < 16; i++ {
		req[i] = 0xFF
	}

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 64)

	n, err := conn.Read(buf)
	if err != nil || n < 32 {
		return nil, errors.New("miio: short reply")
	}

	if binary.BigEndian.Uint16(buf[0:2]) != miioMagic {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	deviceID := binary.BigEndian.Uint32(buf[8:12])
	timestamp := binary.BigEndian.Uint32(buf[12:16])

	fp := &FingerprintResult{
		Product: productXiaomiMiIO,
		Edition: fmt.Sprintf("device_id=%d", deviceID),
		RawJSON: mustMarshalJSON(map[string]any{
			"device_id": deviceID,
			"timestamp": timestamp,
			"raw_hex":   hex.EncodeToString(buf[:n]),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productXiaomiMiIO,
		Banner:      fmt.Sprintf("Xiaomi miIO device_id=%d", deviceID),
		Fingerprint: fp,
	}, nil
}
