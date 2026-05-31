package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	productMySQL = "mysql"
	editionMaria = "mariadb"
)

func init() {
	Register(probeMySQL, 3306)
}

// probeMySQL reads the server greeting packet to extract version, edition,
// and the CLIENT_SSL capability flag.
func probeMySQL(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial MySQL: %w", err)
	}

	defer func() { _ = conn.Close() }()

	header := make([]byte, 4)
	if _, err = conn.Read(header); err != nil {
		return nil, fmt.Errorf("can't read MySQL packet header: %w", err)
	}

	payloadLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if payloadLen <= 0 || payloadLen > 4096 {
		return nil, errors.New("invalid MySQL payload length")
	}

	payload := make([]byte, payloadLen)
	if _, err = conn.Read(payload); err != nil {
		return nil, fmt.Errorf("can't read MySQL payload: %w", err)
	}

	if len(payload) < 16 {
		return nil, errors.New("MySQL payload too short")
	}

	version, capSSL := parseMySQLGreeting(payload)

	authRequired := true

	fp := &FingerprintResult{
		Product:      productMySQL,
		Version:      version,
		AuthRequired: &authRequired,
		TLSRequired:  &capSSL,
		RawJSON: mustMarshalJSON(map[string]any{
			"server_version":   version,
			"capability_flags": map[string]bool{"CLIENT_SSL": capSSL},
		}),
	}

	if strings.Contains(strings.ToLower(version), "mariadb") {
		fp.Edition = editionMaria
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Fingerprint: fp,
	}, nil
}

// parseMySQLGreeting extracts the null-terminated version string and the
// CLIENT_SSL capability flag from a v10 server greeting packet.
func parseMySQLGreeting(payload []byte) (version string, capSSL bool) {
	if idx := bytes.IndexByte(payload[1:], 0); idx >= 0 {
		version = string(payload[1 : 1+idx])
	}

	if len(payload) >= 34 {
		lower := uint16(payload[13]) | uint16(payload[14])<<8
		upper := uint16(payload[31]) | uint16(payload[32])<<8
		flags := uint32(upper)<<16 | uint32(lower)
		capSSL = flags&(1<<11) != 0
	}

	return version, capSSL
}
