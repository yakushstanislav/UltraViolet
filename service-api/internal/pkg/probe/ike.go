package probe

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const productIPsecIKE = "ipsec_ike"

func init() {
	// IKE / ISAKMP on UDP 500 — used by every site-to-site and
	// remote-access VPN concentrator (Cisco ASA, Fortigate, pfSense,
	// strongSwan, libreswan, Mikrotik, Juniper SRX, Palo Alto, SonicWall).
	RegisterUDP(probeIKE, 500)
}

// probeIKE sends an IKEv1 Main Mode SA proposal and looks for an IKE
// reply. The proposal uses the canonical "Main Mode w/ 3DES-SHA-PSK-MODP2"
// transform that ike-scan defaults to — every IKE responder we have
// seen in the wild speaks at least this combination.
//
// Detection logic:
//   - reply length >= 28 bytes,
//   - bytes 0..7 (Initiator SPI) match what we sent (cookie echoed back),
//   - byte 17 (Version) == 0x10 → IKEv1.
//
// We do not attempt to parse the responder SPI or any payload — the goal
// is service detection, not key negotiation. A NOTIFY-INVALID-COOKIE,
// PAYLOAD-MALFORMED, or NO-PROPOSAL-CHOSEN response is just as valid a
// fingerprint as a real SA proposal.
func probeIKE(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	if _, writeErr := conn.Write(ikeMainModeRequest); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 2048)

	n, err := conn.Read(buf)
	if err != nil || n < 28 {
		return nil, errors.New("ike: no IKEv1 reply")
	}

	if !ikeIsResponse(buf[:n]) {
		return &Result{Target: target, Protocol: productIPsecIKE}, nil
	}

	responderSPI := buf[8:16]
	exchangeType := buf[18]
	flags := buf[19]
	msgID := binary.BigEndian.Uint32(buf[20:24])
	respLen := binary.BigEndian.Uint32(buf[24:28])

	fp := &FingerprintResult{
		Product: productIPsecIKE,
		Version: "1.0",
		RawJSON: mustMarshalJSON(map[string]any{
			"version":         "1.0",
			"exchange_type":   exchangeType,
			"flags":           flags,
			"message_id":      msgID,
			"responder_spi":   hex.EncodeToString(responderSPI),
			"reply_length":    respLen,
			"reply_bytes":     n,
			"reply_first_hex": hex.EncodeToString(buf[:min(n, 64)]),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productIPsecIKE,
		Banner:      "IKEv1 / ISAKMP",
		Fingerprint: fp,
	}, nil
}

// ikeIsResponse validates an IKE reply: the initiator cookie must match
// what we sent, and the version byte must indicate IKEv1.
func ikeIsResponse(reply []byte) bool {
	if len(reply) < 28 {
		return false
	}

	for i := range 8 {
		if reply[i] != ikeMainModeRequest[i] {
			return false
		}
	}

	return reply[17] == 0x10
}

// ikeMainModeRequest is a static 80-byte IKEv1 Main Mode SA proposal.
//
// Layout (per RFC 2408 / RFC 2409):
//
//	IKE Header (28 bytes)
//	  Initiator SPI (8) — fixed marker so we can recognise reflections
//	  Responder SPI (8) — zero (initial)
//	  Next Payload (1)  = 0x01 (Security Association)
//	  Version (1)       = 0x10 (IKEv1.0)
//	  Exchange (1)      = 0x02 (Identity Protection / Main Mode)
//	  Flags (1)         = 0x00
//	  Message ID (4)    = 0
//	  Length (4)        = 80
//
//	SA Payload (12 bytes) + Proposal + Transform
//	  Next/Res/Len      = 0x00 0x00 0x0034 (52 bytes total inc. nested)
//	  DOI (4)           = 0x00000001 (IPsec DOI)
//	  Situation (4)     = 0x00000001 (Identity Only)
//
//	Proposal Payload (8 bytes)
//	  Next/Res/Len      = 0x00 0x00 0x0028 (40 bytes inc. transform)
//	  Proposal# / Proto = 0x01 0x01 (ISAKMP)
//	  SPI size / NTrans = 0x00 0x01
//
//	Transform Payload (8 bytes) + 24 bytes of attributes
//	  Next/Res/Len      = 0x00 0x00 0x0020 (32 bytes total)
//	  Transform# / ID   = 0x01 0x01 (KEY_IKE)
//	  Reserved (2)      = 0x0000
//	  Attributes:
//	    Enc=3DES-CBC, Hash=SHA, Auth=PSK, DH=2 (MODP1024),
//	    Life-type=seconds, Life-duration=28800s
var ikeMainModeRequest = []byte{
	0x55, 0x4c, 0x54, 0x52, 0x41, 0x56, 0x4c, 0x54,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01,
	0x10,
	0x02,
	0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x50,

	0x00, 0x00, 0x00, 0x34,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x01,

	0x00, 0x00, 0x00, 0x28,
	0x01, 0x01, 0x00, 0x01,

	0x00, 0x00, 0x00, 0x20,
	0x01, 0x01, 0x00, 0x00,
	0x80, 0x01, 0x00, 0x05,
	0x80, 0x02, 0x00, 0x02,
	0x80, 0x03, 0x00, 0x01,
	0x80, 0x04, 0x00, 0x02,
	0x80, 0x0b, 0x00, 0x01,
	0x80, 0x0c, 0x70, 0x80,
}
