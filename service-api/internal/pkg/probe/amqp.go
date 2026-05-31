package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const productAMQP = "amqp"

func init() {
	Register(probeAMQP, 5672)
}

// probeAMQP sends the AMQP 0-9-1 protocol header and parses the
// Connection.Start frame to extract product, version, and platform from
// the server-properties field table.
func probeAMQP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial AMQP: %w", err)
	}

	defer func() { _ = conn.Close() }()

	if _, err = conn.Write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}); err != nil {
		return nil, fmt.Errorf("can't send AMQP protocol header: %w", err)
	}

	frameHdr := make([]byte, 7)
	if _, err = conn.Read(frameHdr); err != nil {
		return nil, fmt.Errorf("can't read AMQP frame header: %w", err)
	}

	if frameHdr[0] != 1 {
		return nil, fmt.Errorf("unexpected AMQP frame type %d", frameHdr[0])
	}

	size := int(binary.BigEndian.Uint32(frameHdr[3:7]))
	if size < 4 || size > 1<<20 {
		return nil, errors.New("invalid AMQP frame size")
	}

	payload := make([]byte, size)
	if _, err = conn.Read(payload); err != nil {
		return nil, fmt.Errorf("can't read AMQP payload: %w", err)
	}

	endByte := make([]byte, 1)
	if _, err = conn.Read(endByte); err != nil {
		return nil, fmt.Errorf("can't read AMQP frame end: %w", err)
	}

	if endByte[0] != 0xCE {
		return nil, errors.New("invalid AMQP frame end marker")
	}

	if len(payload) < 6 {
		return nil, errors.New("AMQP start payload too short")
	}

	versionMajor := int(payload[4])
	versionMinor := int(payload[5])

	table, _, perr := parseAMQPTable(payload[6:])
	if perr != nil {
		table = map[string]string{}
	}

	product := strings.ToLower(strings.TrimSpace(table["product"]))
	if product == "" {
		product = productAMQP
	}

	authRequired := true

	fp := &FingerprintResult{
		Product:      product,
		Version:      table["version"],
		Edition:      table["platform"],
		AuthRequired: &authRequired,
		RawJSON: mustMarshalJSON(map[string]any{
			"version_major": versionMajor,
			"version_minor": versionMinor,
			"server_properties": map[string]string{
				"product":   table["product"],
				"version":   table["version"],
				"platform":  table["platform"],
				"copyright": table["copyright"],
			},
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Fingerprint: fp,
	}, nil
}

// parseAMQPTable parses an AMQP field-table from the raw bytes. Only short-
// string ('S') fields are decoded; other field types stop iteration early.
func parseAMQPTable(raw []byte) (map[string]string, int, error) {
	if len(raw) < 4 {
		return nil, 0, errors.New("AMQP table too short")
	}

	tableLen := int(binary.BigEndian.Uint32(raw[:4]))
	if tableLen < 0 || len(raw) < 4+tableLen {
		return nil, 0, errors.New("AMQP table truncated")
	}

	data := raw[4 : 4+tableLen]
	out := map[string]string{}
	idx := 0

	for idx < len(data) {
		keyLen := int(data[idx])

		idx++
		if idx+keyLen+1 > len(data) {
			break
		}

		key := string(data[idx : idx+keyLen])
		idx += keyLen
		fieldType := data[idx]
		idx++

		if fieldType != 'S' {
			return out, 4 + tableLen, nil
		}

		if idx+4 > len(data) {
			return out, 4 + idx, nil
		}

		n := int(binary.BigEndian.Uint32(data[idx : idx+4]))

		idx += 4
		if idx+n > len(data) {
			return out, 4 + idx, nil
		}

		out[key] = string(data[idx : idx+n])
		idx += n
	}

	return out, 4 + tableLen, nil
}
