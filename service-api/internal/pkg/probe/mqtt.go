package probe

import (
	"context"
	"encoding/binary"
	"fmt"
)

func init() {
	Register(probeMQTT, 1883)
}

// probeMQTT sends an MQTT 3.1.1 CONNECT with a random clean-session client
// id and parses the CONNACK return code to detect anonymous access.
func probeMQTT(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial MQTT target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	clientID := "uv"

	variableHeader := make([]byte, 0, 10+2+len(clientID))
	variableHeader = append(variableHeader,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04,
		0x02,
		0x00, 0x3c,
	)

	payload := make([]byte, 2+len(clientID))
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(clientID)))
	copy(payload[2:], clientID)

	remaining := append(variableHeader, payload...)

	packet := append([]byte{0x10, byte(len(remaining))}, remaining...)

	if _, writeErr := conn.Write(packet); writeErr != nil {
		return nil, fmt.Errorf("can't write MQTT CONNECT: %w", writeErr)
	}

	resp := make([]byte, 4)

	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		return nil, fmt.Errorf("can't read MQTT CONNACK: %w", err)
	}

	if resp[0] != 0x20 {
		return &Result{
			Target:   target,
			Protocol: "mqtt",
			Banner:   "non-CONNACK first byte",
		}, nil
	}

	returnCode := resp[3]

	authRequired := returnCode == 0x04 || returnCode == 0x05
	anonymous := returnCode == 0x00

	return &Result{
		Target:   target,
		Protocol: "mqtt",
		Fingerprint: &FingerprintResult{
			Product:      "mqtt",
			Version:      "3.1.1",
			AuthRequired: &authRequired,
			Anonymous:    anonymous,
			RawJSON: mustMarshalJSON(map[string]any{
				"return_code":    returnCode,
				"return_meaning": mqttReturnCodeName(returnCode),
			}),
		},
	}, nil
}

func mqttReturnCodeName(code byte) string {
	switch code {
	case 0x00:
		return "accepted"
	case 0x01:
		return "unacceptable_protocol_version"
	case 0x02:
		return "identifier_rejected"
	case 0x03:
		return "server_unavailable"
	case 0x04:
		return "bad_username_or_password"
	case 0x05:
		return "not_authorized"
	}

	return "unknown"
}
