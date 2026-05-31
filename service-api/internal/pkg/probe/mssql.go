package probe

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func init() {
	Register(probeMSSQL, 1433)
}

// probeMSSQL sends a TDS pre-login request and parses the version + encrypt
// options returned by the server.
func probeMSSQL(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial MS-SQL target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	options := []struct {
		token byte
		data  []byte
	}{
		{0x00, []byte{0, 0, 0, 0, 0, 0}},
		{0x01, []byte{0x00}},
		{0x02, []byte{}},
		{0x03, []byte{0x00, 0x00, 0x00, 0x00}},
	}

	optionsHeader := make([]byte, 0, len(options)*5+1)
	body := make([]byte, 0)
	offset := uint16(len(options)*5 + 1)

	for _, opt := range options {
		optionsHeader = append(optionsHeader, opt.token)
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[0:2], offset)
		binary.BigEndian.PutUint16(header[2:4], uint16(len(opt.data)))

		optionsHeader = append(optionsHeader, header...)

		offset += uint16(len(opt.data))

		body = append(body, opt.data...)
	}

	optionsHeader = append(optionsHeader, 0xff)
	payload := append(optionsHeader, body...)

	length := uint16(8 + len(payload))

	packet := make([]byte, 8+len(payload))
	packet[0] = 0x12
	packet[1] = 0x01
	binary.BigEndian.PutUint16(packet[2:4], length)
	packet[6] = 0x00
	packet[7] = 0x00

	copy(packet[8:], payload)

	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("can't write TDS prelogin: %w", err)
	}

	header := make([]byte, 8)
	if _, err := conn.Read(header); err != nil {
		return nil, fmt.Errorf("can't read TDS prelogin header: %w", err)
	}

	if header[0] != 0x04 {
		return &Result{Target: target, Protocol: "mssql"}, nil
	}

	respLen := binary.BigEndian.Uint16(header[2:4])
	if respLen < 8 {
		return &Result{Target: target, Protocol: "mssql"}, nil
	}

	respBody := make([]byte, respLen-8)
	if _, err := conn.Read(respBody); err != nil {
		return nil, fmt.Errorf("can't read TDS prelogin body: %w", err)
	}

	version := mssqlExtractVersion(respBody)
	encryptValue := mssqlExtractByteOption(respBody, 0x01)

	encryptName := mssqlEncryptName(encryptValue)
	tlsRequired := encryptValue == 0x01 || encryptValue == 0x03

	return &Result{
		Target:   target,
		Protocol: "mssql",
		Fingerprint: &FingerprintResult{
			Product:     "mssql",
			Version:     version,
			TLSRequired: boolPtr(tlsRequired),
			RawJSON: mustMarshalJSON(map[string]any{
				"version":          version,
				"encrypt_value":    encryptValue,
				"encrypt_meaning":  encryptName,
				"prelogin_bytes":   len(respBody),
				"raw_prelogin_hex": hex.EncodeToString(respBody),
			}),
		},
	}, nil
}

// mssqlExtractVersion walks the prelogin options table for token 0x00 and
// returns "major.minor.build".
func mssqlExtractVersion(body []byte) string {
	i := 0
	for i < len(body) {
		token := body[i]
		if token == 0xff {
			return ""
		}

		if i+4 >= len(body) {
			return ""
		}

		offset := int(binary.BigEndian.Uint16(body[i+1:i+3])) - 8
		length := int(binary.BigEndian.Uint16(body[i+3 : i+5]))

		if token == 0x00 && offset >= 0 && offset+length <= len(body) && length >= 6 {
			major := body[offset]
			minor := body[offset+1]
			build := binary.BigEndian.Uint16(body[offset+2 : offset+4])

			return fmt.Sprintf("%d.%d.%d", major, minor, build)
		}

		i += 5
	}

	return ""
}

// mssqlExtractByteOption returns the first byte of the specified prelogin
// option, or 0xff if missing.
func mssqlExtractByteOption(body []byte, want byte) byte {
	i := 0
	for i < len(body) {
		token := body[i]
		if token == 0xff {
			return 0xff
		}

		if i+4 >= len(body) {
			return 0xff
		}

		offset := int(binary.BigEndian.Uint16(body[i+1:i+3])) - 8
		length := int(binary.BigEndian.Uint16(body[i+3 : i+5]))

		if token == want && offset >= 0 && offset < len(body) && length >= 1 {
			return body[offset]
		}

		i += 5
	}

	return 0xff
}

func mssqlEncryptName(code byte) string {
	switch code {
	case 0x00:
		return "ENCRYPT_OFF"
	case 0x01:
		return "ENCRYPT_ON"
	case 0x02:
		return "ENCRYPT_NOT_SUP"
	case 0x03:
		return "ENCRYPT_REQ"
	}

	return "unknown"
}
