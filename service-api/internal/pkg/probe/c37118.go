package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const productSynchrophasorPMU = "synchrophasor_pmu"

func init() {
	// 4712 — IEEE C37.118 Synchrophasor PMU/PDC TCP transport.
	Register(probeC37118, 4712)
}

// probeC37118 sends a Command Frame (frame type 0b100, command CFG-2)
// to a Synchrophasor PMU and parses the returned Config-2 frame for the
// station name (STN) and channel counts.
//
// Frame layout (IEEE C37.118.2-2011, section 6):
//
//	SYNC (2B)       0xAA41 = command frame, version 1
//	FRAMESIZE (2B)  total frame length including CHK
//	IDCODE (2B)     PDC/PMU ID we are talking to (we use 1 — common default)
//	SOC (4B)        seconds-of-century, set to 0
//	FRACSEC (4B)    high byte = time quality, low 3B = fractional seconds; 0
//	CMD (2B)        0x0005 = send Config-2 frame
//	CHK (2B)        CRC-CCITT of preceding bytes
func probeC37118(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	frame := buildC37118Command(1, 0x0005)

	if _, writeErr := conn.Write(frame); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 4096)

	n, err := io.ReadAtLeast(conn, buf, 14)
	if err != nil || n < 14 {
		return nil, errors.New("c37.118: short reply")
	}

	sync := binary.BigEndian.Uint16(buf[0:2])

	if sync&0xFF00 != 0xAA00 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	frameType := (sync >> 4) & 0x07

	station := ""

	if frameType == 0x3 {
		// CFG-2 — STN field starts at offset 14 (after time base 4B
		// + NUM_PMU 2B = 6B following the standard 8B header? No: per
		// the spec, after the 14B header (SYNC, FRAMESIZE, IDCODE,
		// SOC, FRACSEC) come TIME_BASE (4B), NUM_PMU (2B), STN (16B).
		offset := 14 + 4 + 2

		if n >= offset+16 {
			station = strings.TrimSpace(strings.TrimRight(string(buf[offset:offset+16]), "\x00 "))
		}
	}

	fp := &FingerprintResult{
		Product: productSynchrophasorPMU,
		Edition: station,
		RawJSON: mustMarshalJSON(map[string]any{
			"frame_type": frameType,
			"reply_len":  n,
			"station":    station,
		}),
	}

	banner := "IEEE C37.118 PMU"
	if station != "" {
		banner = "IEEE C37.118 PMU " + station
	}

	return &Result{
		Target:      target,
		Protocol:    productSynchrophasorPMU,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// buildC37118Command assembles a command frame requesting one of the
// C37.118 admin commands (CMD field).
func buildC37118Command(idcode, cmd uint16) []byte {
	frame := make([]byte, 18)
	binary.BigEndian.PutUint16(frame[0:2], 0xAA41)
	binary.BigEndian.PutUint16(frame[2:4], 18)
	binary.BigEndian.PutUint16(frame[4:6], idcode)
	binary.BigEndian.PutUint32(frame[6:10], 0)
	binary.BigEndian.PutUint32(frame[10:14], 0)
	binary.BigEndian.PutUint16(frame[14:16], cmd)

	binary.BigEndian.PutUint16(frame[16:18], crcCCITT(frame[:16]))

	return frame
}

// crcCCITT computes the CRC-CCITT (poly 0x1021, init 0xFFFF) used by
// IEEE C37.118 frames.
func crcCCITT(data []byte) uint16 {
	crc := uint16(0xFFFF)

	for _, b := range data {
		crc ^= uint16(b) << 8

		for range 8 {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}

	return crc
}
