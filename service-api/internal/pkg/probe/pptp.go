package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

const productPPTP = "pptp"

func init() {
	// 1723 — PPTP control connection (RFC 2637). Common on legacy VPN
	// concentrators (MikroTik, MS RRAS, Cisco PIX, Fortinet).
	Register(probePPTP, 1723)
}

const (
	pptpMagicCookie     uint32 = 0x1A2B3C4D
	pptpMessageTypeCtrl uint16 = 1
	pptpMessageSCCRQ    uint16 = 1
	pptpMessageSCCRP    uint16 = 2
)

// probePPTP sends Start-Control-Connection-Request and parses the
// Start-Control-Connection-Reply (RFC 2637 §2.5–§2.6). The reply carries
// the server's firmware revision, host name and vendor name strings —
// all three are useful for CVE matching of MikroTik / TP-Link / Cisco
// firmware. Anything other than a SCCRP is treated as non-PPTP.
func probePPTP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial PPTP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	if _, writeErr := conn.Write(pptpSCCRQ()); writeErr != nil {
		return nil, fmt.Errorf("can't send PPTP SCCRQ: %w", writeErr)
	}

	header := make([]byte, 12)
	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return nil, fmt.Errorf("can't read PPTP reply header: %w", readErr)
	}

	length := binary.BigEndian.Uint16(header[0:2])
	pduType := binary.BigEndian.Uint16(header[2:4])
	cookie := binary.BigEndian.Uint32(header[4:8])
	ctrlType := binary.BigEndian.Uint16(header[8:10])

	if cookie != pptpMagicCookie || pduType != pptpMessageTypeCtrl {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	if length < 156 || length > 4096 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	body := make([]byte, int(length)-12)
	if _, readErr := io.ReadFull(conn, body); readErr != nil {
		return nil, fmt.Errorf("can't read PPTP reply body: %w", readErr)
	}

	if ctrlType != pptpMessageSCCRP || len(body) < 144 {
		return &Result{Target: target, Protocol: productPPTP, Banner: "PPTP control"}, nil
	}

	// SCCRP body layout (post-control-type, body bytes from offset 0):
	//   0:   protocol_version (uint16)
	//   2:   result_code (uint8)
	//   3:   error_code  (uint8)
	//   4:   framing_capabilities (uint32)
	//   8:   bearer_capabilities  (uint32)
	//  12:   maximum_channels (uint16)
	//  14:   firmware_revision (uint16)
	//  16:   host_name [64]
	//  80:   vendor_name [64]
	protoVersion := binary.BigEndian.Uint16(body[0:2])
	resultCode := body[2]
	errorCode := body[3]
	maxChannels := binary.BigEndian.Uint16(body[12:14])
	firmwareRev := binary.BigEndian.Uint16(body[14:16])
	hostName := pptpDecodeString(body[16:80])
	vendor := pptpDecodeString(body[80:144])

	fp := &FingerprintResult{
		Product: productPPTP,
		Version: pptpVersionString(protoVersion),
		RawJSON: mustMarshalJSON(map[string]any{
			"protocol_version": protoVersion,
			"result_code":      resultCode,
			"error_code":       errorCode,
			"max_channels":     maxChannels,
			"firmware_rev":     firmwareRev,
			"host_name":        hostName,
			"vendor_name":      vendor,
		}),
	}

	banner := strings.TrimSpace("PPTP " + vendor + " " + hostName)

	return &Result{
		Target:      target,
		Protocol:    productPPTP,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// pptpSCCRQ assembles the 156-byte Start-Control-Connection-Request PDU.
// We advertise PPP-AC framing and no bearer-specific capabilities; that is
// the safest combo that elicits a SCCRP from every implementation in the
// wild without surfacing optional negotiation extensions.
func pptpSCCRQ() []byte {
	out := make([]byte, 156)

	binary.BigEndian.PutUint16(out[0:2], 156)                 // length
	binary.BigEndian.PutUint16(out[2:4], pptpMessageTypeCtrl) // message type
	binary.BigEndian.PutUint32(out[4:8], pptpMagicCookie)     // magic cookie
	binary.BigEndian.PutUint16(out[8:10], pptpMessageSCCRQ)   // control type
	binary.BigEndian.PutUint16(out[10:12], 0)                 // reserved
	binary.BigEndian.PutUint16(out[12:14], 0x0100)            // protocol version 1.0
	binary.BigEndian.PutUint16(out[14:16], 0)                 // reserved
	binary.BigEndian.PutUint32(out[16:20], 0x00000001)        // framing capabilities = async
	binary.BigEndian.PutUint32(out[20:24], 0x00000001)        // bearer capabilities = analog
	binary.BigEndian.PutUint16(out[24:26], 1)                 // maximum channels
	binary.BigEndian.PutUint16(out[26:28], 1)                 // firmware revision
	copy(out[28:92], []byte("uv-scanner\x00"))                // host name
	copy(out[92:156], []byte("UltraViolet probe\x00"))        // vendor name

	return out
}

func pptpDecodeString(raw []byte) string {
	idx := bytes.IndexByte(raw, 0)
	if idx >= 0 {
		raw = raw[:idx]
	}

	return strings.TrimSpace(string(raw))
}

func pptpVersionString(v uint16) string {
	return fmt.Sprintf("%d.%d", v>>8, v&0xFF)
}
