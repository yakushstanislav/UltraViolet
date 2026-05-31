package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

const productS7 = "siemens_simatic"

func init() {
	Register(probeS7Comm, 102)
}

// probeS7Comm walks the Siemens S7Comm bring-up sequence (TPKT/RFC1006 →
// ISO-on-TCP COTP CR/CC → S7 Setup Communication → Read SZL 0x011A).
//
// Result on success: Product=siemens_simatic, Version=firmware "VV.V.V",
// Edition=MLFB order number (e.g. "6ES7 315-2EH14-0AB0"). Detection-only
// success (only COTP CC observed) yields Product=siemens_simatic without
// a version.
//
// All three packet stages are static — S7-300/400/1200/1500 CPUs respond
// to the same byte streams. Rack/slot defaults to 0/1 (CPU TSAP 0x0102),
// which is what the SIMATIC Manager uses out of the box and what works
// on every CPU we have ever seen exposed.
func probeS7Comm(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	if _, writeErr := conn.Write(s7COTPConnectRequest); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 1024)

	n, err := io.ReadAtLeast(conn, buf, 7)
	if err != nil || n < 7 {
		return nil, errors.New("s7: short COTP CC")
	}

	if !isCOTPConnectConfirm(buf[:n]) {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	// COTP confirmed → we are talking to an S7 stack. Even if the
	// follow-up Setup/SZL is dropped, the protocol is identified.
	fp := &FingerprintResult{Product: productS7}

	if _, writeErr := conn.Write(s7SetupCommunication); writeErr != nil {
		return s7Result(target, fp, "S7Comm COTP CC"), nil
	}

	n, err = io.ReadAtLeast(conn, buf, 19)
	if err != nil || n < 19 || !isS7Ack(buf[:n]) {
		return s7Result(target, fp, "S7Comm Setup pending"), nil
	}

	if _, writeErr := conn.Write(s7ReadSZL011A); writeErr != nil {
		return s7Result(target, fp, "S7Comm Setup ack"), nil
	}

	n, err = io.ReadAtLeast(conn, buf, 32)
	if err != nil || n < 32 {
		return s7Result(target, fp, "S7Comm Setup ack"), nil
	}

	mlfb, version := parseSZL011A(buf[:n])
	if mlfb != "" {
		fp.Edition = mlfb
	}

	if version != "" {
		fp.Version = version
	}

	fp.RawJSON = mustMarshalJSON(map[string]any{
		"mlfb":    mlfb,
		"version": version,
	})

	banner := "Siemens SIMATIC S7"

	if mlfb != "" {
		banner = "Siemens SIMATIC " + mlfb
	}

	return s7Result(target, fp, banner), nil
}

func s7Result(target Target, fp *FingerprintResult, banner string) *Result {
	return &Result{
		Target:      target,
		Protocol:    productS7,
		Banner:      banner,
		Fingerprint: fp,
	}
}

// s7COTPConnectRequest is the TPKT/COTP CR payload that opens a session
// to the CPU on rack 0, slot 1. The byte sequence matches what SIMATIC
// Manager / WinCC send on first contact.
//
//	TPKT  : 03 00 00 16            (version, reserved, length=22)
//	COTP  : 11 E0 00 00 00 01 00   (LI=17, CR, dst-ref, src-ref, class)
//	param : C0 01 0A               (TPDU size 1024)
//	param : C1 02 01 00            (source TSAP 0x0100)
//	param : C2 02 01 02            (destination TSAP 0x0102 → CPU rack 0, slot 1)
var s7COTPConnectRequest = []byte{
	0x03, 0x00, 0x00, 0x16,
	0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
	0xC0, 0x01, 0x0A,
	0xC1, 0x02, 0x01, 0x00,
	0xC2, 0x02, 0x01, 0x02,
}

// s7SetupCommunication is the S7Comm "Setup Communication" job: function
// 0xF0, maxAmqCaller=1, maxAmqCallee=1, PDU length 0x03C0 (960 bytes).
//
//	TPKT  : 03 00 00 19
//	COTP  : 02 F0 80              (LI=2, DT, EOT)
//	S7    : 32 01 00 00 00 00 00 08 00 00      (header: Job, paramLen=8)
//	param : F0 00 00 01 00 01 03 C0
var s7SetupCommunication = []byte{
	0x03, 0x00, 0x00, 0x19,
	0x02, 0xF0, 0x80,
	0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
	0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0xC0,
}

// s7ReadSZL011A reads SZL ID 0x0011 (Module Identification), index 0x001A,
// which carries the MLFB order number and firmware version of the CPU.
// Userdata function group 4 (CPU functions), subfunction 1 (Read SZL).
//
//	TPKT  : 03 00 00 21
//	COTP  : 02 F0 80
//	S7 hdr: 32 07 00 00 00 00 00 08 00 08       (Userdata, paramLen=8, dataLen=8)
//	param : 00 01 12 04 11 44 01 00             (Userdata param block)
//	data  : 00 01 12 08 12 44 01 01 00 00 00 00 (Read SZL request, SZL-ID/Idx tail)
//
// Many vendors document this exact frame as the de-facto "ask the PLC who
// you are" call.
var s7ReadSZL011A = []byte{
	0x03, 0x00, 0x00, 0x21,
	0x02, 0xF0, 0x80,
	0x32, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08,
	0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00,
	0x00, 0x01, 0x12, 0x08, 0x12, 0x44, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00,
}

// isCOTPConnectConfirm reports whether the response is a valid TPKT-framed
// COTP Connection Confirm (PDU type 0xD0).
func isCOTPConnectConfirm(b []byte) bool {
	if len(b) < 7 || b[0] != 0x03 || b[1] != 0x00 {
		return false
	}

	return b[5]&0xF0 == 0xD0
}

// isS7Ack reports whether the response is a Setup Communication ACK_DATA
// (ROSCTR 0x03) — the protocol-id byte at offset 7 must be 0x32.
func isS7Ack(b []byte) bool {
	if len(b) < 9 {
		return false
	}

	return b[7] == 0x32 && b[8] == 0x03
}

// parseSZL011A pulls the MLFB and firmware version out of a Read SZL
// response. The data section starts at offset 24 of the S7 payload after
// the TPKT/COTP/header chain.
//
// Real-world frames put the first SZL item at offset 31 of the entire
// frame (TPKT 4 + COTP 3 + header 12 + param 12 = 31). The item layout
// after the SZL preamble (id 2B + index 2B + item length 2B + item count
// 2B) is:
//
//	bytes 0..19  MLFB ASCII (space-padded)
//	bytes 20..21 BGTyp constant (0x00C0)
//	bytes 22..23 V1V2 (BCD bytes, e.g. 0x03 0x02 → "3.2")
//	bytes 24..25 V3 (BCD, e.g. 0x00 0x05 → "5")
//
// The function is forgiving: any unexpected byte yields an empty string
// and the caller falls back to a version-less fingerprint.
func parseSZL011A(b []byte) (mlfb, version string) {
	const (
		headerOffset = 31
		itemSize     = 28
	)

	if len(b) < headerOffset+itemSize {
		return "", ""
	}

	// The first 8 bytes of the data section are the SZL preamble
	// (id/index/item-length/item-count). Each item starts with a 2-byte
	// item index followed by 28 bytes of payload.
	itemStart := headerOffset + 2

	if len(b) < itemStart+itemSize {
		return "", ""
	}

	item := b[itemStart : itemStart+itemSize]

	mlfb = strings.TrimSpace(strings.TrimRight(string(item[0:20]), "\x00 "))

	v1 := bcdToInt(item[22])
	v2 := bcdToInt(item[23])
	v3 := bcdToInt(item[25])

	if v1 > 0 || v2 > 0 || v3 > 0 {
		version = fmt.Sprintf("%d.%d.%d", v1, v2, v3)
	}

	return mlfb, version
}

// bcdToInt extracts the two BCD digits packed into a byte.
func bcdToInt(b byte) int {
	high := int(b >> 4)
	low := int(b & 0x0F)

	return high*10 + low
}
