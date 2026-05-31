package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
)

const productDNP3 = "dnp3"

func init() {
	Register(probeDNP3, 20000)
}

// probeDNP3 fires a single Link Layer "Request Link Status" PDU. Every
// DNP3 outstation (RTU/IED in utility SCADA networks) has to respond with
// a Link Status frame regardless of authentication state, which makes
// this the canonical "is this DNP3?" check.
//
// Wire format (IEEE 1815-2012, section 8 — Data Link Layer):
//
//	start  uint16  = 0x0564
//	length uint8   = 5
//	control uint8  = 0xC9  (DIR=1 PRM=1 FCB=0 FCV=0 FUNC=9 RequestLinkStatus)
//	dest   uint16 LE  (we use 0x0001)
//	src    uint16 LE  (we use 0x0000)
//	crc    uint16 LE
//
// Response is a Link Status PDU with FUNC=11 (0x0B) in the response
// control byte. We don't parse the application layer — DNP3 mandates a
// secure-auth handshake before the master can pull device info — but the
// link-layer reply already exposes the destination/source addresses and
// firmware can be inferred from the secondary station address mapping in
// many vendor docs.
func probeDNP3(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	req := buildDNP3LinkStatus()

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 64)

	n, err := io.ReadAtLeast(conn, buf, 10)
	if err != nil || n < 10 {
		return nil, errors.New("dnp3: short reply")
	}

	if buf[0] != 0x05 || buf[1] != 0x64 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	control := buf[3]
	dest := binary.LittleEndian.Uint16(buf[4:6])
	src := binary.LittleEndian.Uint16(buf[6:8])

	fp := &FingerprintResult{
		Product: productDNP3,
		Edition: "addr " + strconv.Itoa(int(src)) + "->" + strconv.Itoa(int(dest)),
		RawJSON: mustMarshalJSON(map[string]any{
			"control": control,
			"dest":    dest,
			"src":     src,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productDNP3,
		Banner:      "DNP3 link status",
		Fingerprint: fp,
	}, nil
}

// buildDNP3LinkStatus builds a Request-Link-Status PDU with the DNP3 CRC
// (poly 0x3D65, init 0x0000, output XOR 0xFFFF, LSB-first) over the
// 5-byte fixed header.
func buildDNP3LinkStatus() []byte {
	const (
		start    uint16 = 0x0564
		length   uint8  = 5
		control  uint8  = 0xC9
		destAddr uint16 = 0x0001
		srcAddr  uint16 = 0x0000
	)

	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[0:2], start)
	header[2] = length
	header[3] = control
	binary.LittleEndian.PutUint16(header[4:6], destAddr)
	binary.LittleEndian.PutUint16(header[6:8], srcAddr)

	crc := dnp3CRC(header[2:8])

	out := make([]byte, 10)
	copy(out, header)
	binary.LittleEndian.PutUint16(out[8:10], crc)

	return out
}

// dnp3CRC computes the CRC-16 with the DNP3 polynomial — required by the
// link layer for every block of <=16 bytes. The table is precomputed at
// init time to keep the implementation a single read-loop.
var dnp3CRCTable = func() [256]uint16 {
	var t [256]uint16

	for i := range 256 {
		c := uint16(i)

		for range 8 {
			if c&0x0001 != 0 {
				c = (c >> 1) ^ 0xA6BC
			} else {
				c >>= 1
			}
		}

		t[i] = c
	}

	return t
}()

func dnp3CRC(b []byte) uint16 {
	crc := uint16(0)

	for _, x := range b {
		crc = (crc >> 8) ^ dnp3CRCTable[byte(crc)^x]
	}

	return ^crc
}
