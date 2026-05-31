package probe

import (
	"context"
	"encoding/binary"
	"fmt"
)

func init() {
	Register(probeSMB, 445)
}

// probeSMB sends an SMB2 NEGOTIATE_REQUEST and parses the dialect, signing
// requirement and capabilities from the response.
func probeSMB(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial SMB target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	smb2 := buildSMB2Negotiate()

	packet := make([]byte, 4+len(smb2))
	binary.BigEndian.PutUint32(packet[:4], uint32(len(smb2)))
	packet[0] = 0x00

	copy(packet[4:], smb2)

	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("can't write SMB negotiate: %w", err)
	}

	respHeader := make([]byte, 4)
	if _, err := conn.Read(respHeader); err != nil {
		return nil, fmt.Errorf("can't read SMB header: %w", err)
	}

	respLen := int(binary.BigEndian.Uint32(respHeader)) & 0x00ffffff
	if respLen < 64 || respLen > 65536 {
		return &Result{Target: target, Protocol: "smb"}, nil
	}

	body := make([]byte, respLen)
	if _, err := conn.Read(body); err != nil {
		return nil, fmt.Errorf("can't read SMB body: %w", err)
	}

	if len(body) < 68 {
		return &Result{Target: target, Protocol: "smb"}, nil
	}

	if body[0] != 0xfe || body[1] != 'S' || body[2] != 'M' || body[3] != 'B' {
		return &Result{Target: target, Protocol: "smb", Banner: string(body[:4])}, nil
	}

	dialect := binary.LittleEndian.Uint16(body[68:70])
	securityMode := binary.LittleEndian.Uint16(body[70:72])
	capabilities := binary.LittleEndian.Uint32(body[76:80])

	signingRequired := securityMode&0x0002 != 0
	signingEnabled := securityMode&0x0001 != 0
	supportsEncryption := capabilities&0x00000040 != 0

	return &Result{
		Target:   target,
		Protocol: "smb",
		Fingerprint: &FingerprintResult{
			Product:      "smb",
			Version:      smb2DialectName(dialect),
			AuthRequired: boolPtr(true),
			TLSRequired:  boolPtr(false),
			RawJSON: mustMarshalJSON(map[string]any{
				"dialect":             fmt.Sprintf("0x%04x", dialect),
				"signing_enabled":     signingEnabled,
				"signing_required":    signingRequired,
				"supports_encryption": supportsEncryption,
				"capabilities":        fmt.Sprintf("0x%08x", capabilities),
			}),
		},
	}, nil
}

// buildSMB2Negotiate returns a minimal SMB2 NEGOTIATE_REQUEST advertising
// the common modern dialects (2.0.2 through 3.1.1).
func buildSMB2Negotiate() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}

	header := make([]byte, 0, 64+36+2*len(dialects))
	header = append(header,
		0xfe, 'S', 'M', 'B',
		64, 0,
		0, 0,
		0, 0, 0, 0,
		0, 0,
		0, 0,
		0, 0, 0, 0,
		1, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	)

	body := make([]byte, 36+2*len(dialects))
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:6], 0x0001)

	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:36+i*2+2], d)
	}

	return append(header, body...)
}

func smb2DialectName(dialect uint16) string {
	switch dialect {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	}

	return fmt.Sprintf("SMB dialect 0x%04x", dialect)
}
