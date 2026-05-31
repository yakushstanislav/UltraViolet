package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
)

const productDLMSCOSEM = "dlms_cosem"

func init() {
	// 4059 — DLMS/COSEM wrapper layer over TCP (per IEC 62056-47).
	// 4060 — the TLS-secured variant. We probe both with the same
	// open-connection-request payload.
	Register(probeDLMS, 4059, 4060)
}

// probeDLMS sends an Association Request (AARQ) APDU wrapped in the
// DLMS/COSEM Wrapper Protocol Data Unit and checks for an AARE reply or
// any DLMS-shaped payload.
//
// Wrapper layout (IEC 62056-47):
//
//	uint16 BE   version  = 0x0001
//	uint16 BE   src wPort = 0x0001 (public client)
//	uint16 BE   dst wPort = 0x0001 (management logical device)
//	uint16 BE   length    = body length
//	body                  = COSEM APDU
//
// AARQ payload (per Green Book): tag 0x60 followed by basic association
// items. The shortest valid request that interrogates the public client
// has tag 0x60, length 1D and the application-context-name OID for
// LN referencing with no ciphering.
func probeDLMS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	aarq := []byte{
		0x60, 0x1D, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85,
		0x74, 0x05, 0x08, 0x01, 0x01, 0xBE, 0x10, 0x04,
		0x0E, 0x01, 0x00, 0x00, 0x00, 0x06, 0x5F, 0x1F,
		0x04, 0x00, 0x00, 0x18, 0x1D, 0xFF, 0xFF,
	}

	wrapper := make([]byte, 8, 8+len(aarq))
	binary.BigEndian.PutUint16(wrapper[0:2], 0x0001)
	binary.BigEndian.PutUint16(wrapper[2:4], 0x0001)
	binary.BigEndian.PutUint16(wrapper[4:6], 0x0001)
	binary.BigEndian.PutUint16(wrapper[6:8], uint16(len(aarq)))

	wrapper = append(wrapper, aarq...)

	if _, writeErr := conn.Write(wrapper); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 1024)

	n, err := io.ReadAtLeast(conn, buf, 8)
	if err != nil || n < 8 {
		return nil, errors.New("dlms: short reply")
	}

	if binary.BigEndian.Uint16(buf[0:2]) != 0x0001 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	// AARE response tag is 0x61.
	if n >= 9 && buf[8] != 0x61 {
		// Some meters reject with a Confirmed-Service-Error (tag 0x0E)
		// or RLRE (tag 0x63); both still confirm DLMS/COSEM.
		switch buf[8] {
		case 0x0E, 0x63:
		default:
			return &Result{Target: target, Protocol: protocolTCP}, nil
		}
	}

	fp := &FingerprintResult{
		Product: productDLMSCOSEM,
		RawJSON: mustMarshalJSON(map[string]any{
			"reply_len":   n,
			"reply_tag":   buf[8],
			"wrapper_ver": binary.BigEndian.Uint16(buf[0:2]),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productDLMSCOSEM,
		Banner:      "DLMS/COSEM meter",
		Fingerprint: fp,
	}, nil
}
