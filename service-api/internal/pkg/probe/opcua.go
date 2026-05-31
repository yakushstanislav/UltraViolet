package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
)

const productOPCUA = "opcua"

func init() {
	Register(probeOPCUA, 4840)
}

// probeOPCUA performs the bare-minimum OPC UA TCP handshake — HELLO then
// reads back ACK — to confirm the protocol and capture the server's
// transport-layer parameters. Going further than ACK (OpenSecureChannel /
// GetEndpoints) requires a full SecureChannel which is well beyond what a
// fingerprinter should attempt.
//
// Reference: OPC 10000-6, section 7.1.2 — Hello Message.
//
//	MessageHeader  3 bytes "HEL" + 1 byte chunk type 'F' + uint32 size
//	HelloMessage   uint32 protoVer
//	               uint32 receiveBufferSize
//	               uint32 sendBufferSize
//	               uint32 maxMessageSize
//	               uint32 maxChunkCount
//	               UAString endpointUrl
//
// We report Product="opcua" with no Version. cvematch will still pick up
// applicability statements that don't pin a version (which OPC UA stack
// CVEs frequently don't).
func probeOPCUA(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	endpoint := "opc.tcp://" + target.IP.String() + ":" + strconv.Itoa(int(target.Port))

	msg := buildOPCUAHello(endpoint)

	if _, writeErr := conn.Write(msg); writeErr != nil {
		return nil, writeErr
	}

	header := make([]byte, 8)
	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return nil, readErr
	}

	if string(header[:3]) != "ACK" && string(header[:3]) != "ERR" {
		// Not OPC UA — quietly fall through to a TCP banner.
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	size := binary.LittleEndian.Uint32(header[4:8])
	if size < 8 || size > 4096 {
		size = 8
	}

	body := make([]byte, int(size)-8)
	if len(body) > 0 {
		_, _ = io.ReadFull(conn, body)
	}

	fp := &FingerprintResult{
		Product: productOPCUA,
		RawJSON: mustMarshalJSON(map[string]any{
			"ack_type":   string(header[:3]),
			"chunk_type": string(header[3:4]),
			"size":       size,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productOPCUA,
		Banner:      "OPC UA " + string(header[:3]),
		Fingerprint: fp,
	}, nil
}

func buildOPCUAHello(endpoint string) []byte {
	if len(endpoint) > 65535 {
		endpoint = endpoint[:65535]
	}

	url := []byte(endpoint)
	totalSize := 8 + 4 + 4 + 4 + 4 + 4 + 4 + len(url)

	msg := make([]byte, totalSize)
	copy(msg[0:3], "HEL")
	msg[3] = 'F'

	binary.LittleEndian.PutUint32(msg[4:8], uint32(totalSize))
	binary.LittleEndian.PutUint32(msg[8:12], 0)                 // ProtocolVersion
	binary.LittleEndian.PutUint32(msg[12:16], 65536)            // ReceiveBufferSize
	binary.LittleEndian.PutUint32(msg[16:20], 65536)            // SendBufferSize
	binary.LittleEndian.PutUint32(msg[20:24], 16777216)         // MaxMessageSize
	binary.LittleEndian.PutUint32(msg[24:28], 5000)             // MaxChunkCount
	binary.LittleEndian.PutUint32(msg[28:32], uint32(len(url))) // EndpointUrl length
	copy(msg[32:], url)

	if len(msg) != totalSize {
		return msg[:totalSize]
	}

	_ = errors.New

	return msg
}
