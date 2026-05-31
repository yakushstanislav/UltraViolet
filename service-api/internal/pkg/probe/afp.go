package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const productAFP = "apple_filing_protocol"

func init() {
	// 548 — Apple Filing Protocol (legacy macOS / Netatalk / TimeMachine).
	Register(probeAFP, 548)
}

// probeAFP issues a DSI Open Session followed by a GetStatus payload —
// the canonical AFP "what server are you" call. Reply carries a server
// signature, machine type, supported AFP versions, and the server name.
//
// DSI header (RFC 1057-shaped, 16B):
//
//	flags(1)      0x00 request / 0x01 reply
//	command(1)    0x03 GetStatus
//	requestID(2)  arbitrary
//	errorCode(4)  request: dataOffset; reply: errorCode
//	dataLen(4)
//	reserved(4)   0
func probeAFP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	header := make([]byte, 16)

	header[0] = 0x00
	header[1] = 0x03

	binary.BigEndian.PutUint16(header[2:4], 0x0001)
	binary.BigEndian.PutUint32(header[4:8], 0)
	binary.BigEndian.PutUint32(header[8:12], 0)
	binary.BigEndian.PutUint32(header[12:16], 0)

	if _, writeErr := conn.Write(header); writeErr != nil {
		return nil, writeErr
	}

	respHeader := make([]byte, 16)

	if _, readErr := io.ReadFull(conn, respHeader); readErr != nil {
		return nil, errors.New("afp: short DSI header")
	}

	if respHeader[0]&0x01 != 0x01 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	dataLen := binary.BigEndian.Uint32(respHeader[8:12])
	if dataLen == 0 || dataLen > 65535 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	body := make([]byte, dataLen)

	if _, readErr := io.ReadFull(conn, body); readErr != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	serverName, machineType := parseAFPStatus(body)

	fp := &FingerprintResult{
		Product: productAFP,
		Edition: machineType,
		RawJSON: mustMarshalJSON(map[string]any{
			"server_name":  serverName,
			"machine_type": machineType,
		}),
	}

	banner := "AFP " + machineType

	if serverName != "" {
		banner = banner + " " + serverName
	}

	return &Result{
		Target:      target,
		Protocol:    productAFP,
		Banner:      strings.TrimSpace(banner),
		Fingerprint: fp,
	}, nil
}

// parseAFPStatus decodes the AFP GetStatus response, extracting the
// server name (offset by MachineOffset → Pascal string) and machine type
// (offset by MachineOffset → Pascal string).
func parseAFPStatus(b []byte) (string, string) {
	if len(b) < 8 {
		return "", ""
	}

	machineOff := int(binary.BigEndian.Uint16(b[0:2]))
	versionOff := int(binary.BigEndian.Uint16(b[2:4]))

	_ = versionOff

	machine := pascalString(b, machineOff)

	srvNameOff := -1

	for i := 0; i+1 < len(b); i++ {
		if b[i] == 0 && b[i+1] >= 1 && b[i+1] <= 33 {
			candidate := pascalString(b, i+1)
			if isPrintableASCII(candidate) && candidate != machine {
				srvNameOff = i + 1

				break
			}
		}
	}

	server := ""
	if srvNameOff >= 0 {
		server = pascalString(b, srvNameOff)
	}

	return server, machine
}

func pascalString(b []byte, off int) string {
	if off < 0 || off >= len(b) {
		return ""
	}

	length := int(b[off])
	if off+1+length > len(b) {
		return ""
	}

	return string(b[off+1 : off+1+length])
}

func isPrintableASCII(s string) bool {
	if s == "" {
		return false
	}

	for _, c := range s {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}

	return true
}
