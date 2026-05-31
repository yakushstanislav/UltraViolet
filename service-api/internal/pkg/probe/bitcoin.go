package probe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const productBitcoinCore = "bitcoin_core"

func init() {
	// 8333 — Bitcoin mainnet P2P. Tracking other chains (litecoin 9333,
	// dogecoin 22556, monero 18080) is left to derived.go aliases.
	Register(probeBitcoin, 8333)
}

// probeBitcoin sends a Bitcoin `version` message and inspects the peer's
// reply for the user-agent field that identifies the implementation.
//
// Wire format (Bitcoin Core net.h):
//
//	magic     4B  0xF9 0xBE 0xB4 0xD9 (mainnet)
//	command  12B  ASCII space-padded
//	length    4B  LE
//	checksum  4B  first 4B of double-SHA256(payload)
//	payload   ...
//
// `version` payload carries:
//
//	int32  version
//	uint64 services
//	int64  timestamp
//	addr_recv (26B)
//	addr_from (26B)
//	uint64 nonce
//	var_str user_agent
//	int32  start_height
//	bool   relay
func probeBitcoin(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	payload := buildBitcoinVersionPayload()

	frame := buildBitcoinFrame([]byte("version"), payload)

	if _, writeErr := conn.Write(frame); writeErr != nil {
		return nil, writeErr
	}

	header := make([]byte, 24)

	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return nil, errors.New("bitcoin: short header")
	}

	if !isBitcoinMagic(header[:4]) {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	command := strings.TrimRight(string(header[4:16]), "\x00")
	length := binary.LittleEndian.Uint32(header[16:20])

	if length > 1<<20 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	body := make([]byte, length)
	if length > 0 {
		_, _ = io.ReadFull(conn, body)
	}

	userAgent, startHeight := "", int32(0)

	if command == "version" {
		userAgent, startHeight = parseBitcoinVersion(body)
	}

	product := productBitcoinCore
	if hint := bitcoinUserAgentHint(userAgent); hint != "" {
		product = hint
	}

	version := extractBitcoinVersion(userAgent)

	fp := &FingerprintResult{
		Product: product,
		Version: version,
		Edition: userAgent,
		RawJSON: mustMarshalJSON(map[string]any{
			"command":      command,
			"user_agent":   userAgent,
			"start_height": startHeight,
		}),
	}

	banner := "Bitcoin " + userAgent

	return &Result{
		Target:      target,
		Protocol:    product,
		Banner:      strings.TrimSpace(banner),
		Fingerprint: fp,
	}, nil
}

// buildBitcoinVersionPayload assembles a minimal Bitcoin version message.
func buildBitcoinVersionPayload() []byte {
	payload := make([]byte, 0, 100)

	tmp := make([]byte, 8)

	binary.LittleEndian.PutUint32(tmp[:4], 70016)
	payload = append(payload, tmp[:4]...)

	binary.LittleEndian.PutUint64(tmp[:8], 0)
	payload = append(payload, tmp[:8]...)

	binary.LittleEndian.PutUint64(tmp[:8], uint64(0))
	payload = append(payload, tmp[:8]...)

	payload = append(payload, make([]byte, 26)...)
	payload = append(payload, make([]byte, 26)...)

	binary.LittleEndian.PutUint64(tmp[:8], 0xCAFEBABE)
	payload = append(payload, tmp[:8]...)

	userAgent := "/UltraViolet:0.1/"

	payload = append(payload, byte(len(userAgent)))
	payload = append(payload, userAgent...)

	binary.LittleEndian.PutUint32(tmp[:4], 0)
	payload = append(payload, tmp[:4]...)

	payload = append(payload, 0x00)

	return payload
}

// buildBitcoinFrame wraps payload in the Bitcoin P2P framing.
func buildBitcoinFrame(command, payload []byte) []byte {
	frame := make([]byte, 24, 24+len(payload))

	frame[0] = 0xF9
	frame[1] = 0xBE
	frame[2] = 0xB4
	frame[3] = 0xD9

	copy(frame[4:16], command)

	binary.LittleEndian.PutUint32(frame[16:20], uint32(len(payload)))

	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])

	copy(frame[20:24], second[:4])

	return append(frame, payload...)
}

// isBitcoinMagic checks for any major Bitcoin-family network magic
// (mainnet / testnet / signet / regtest / namecoin / litecoin).
func isBitcoinMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}

	magic := binary.LittleEndian.Uint32(b)

	switch magic {
	case 0xD9B4BEF9, 0xDAB5BFFA, 0x0709110B, 0xFABFB5DA, 0xFEB4BEF9, 0xDBB6C0FB:
		return true
	}

	return false
}

// parseBitcoinVersion pulls user-agent and start-height out of a version
// payload. Returns empty values on malformed input.
func parseBitcoinVersion(b []byte) (string, int32) {
	const fixedHeader = 4 + 8 + 8 + 26 + 26 + 8

	if len(b) < fixedHeader+1 {
		return "", 0
	}

	uaLen := int(b[fixedHeader])
	off := fixedHeader + 1

	if off+uaLen > len(b) {
		return "", 0
	}

	userAgent := string(b[off : off+uaLen])
	off += uaLen

	if off+4 > len(b) {
		return userAgent, 0
	}

	height := int32(binary.LittleEndian.Uint32(b[off : off+4]))

	return userAgent, height
}

// bitcoinUserAgentHint maps known user-agent prefixes to cpemap keys.
func bitcoinUserAgentHint(ua string) string {
	lower := strings.ToLower(ua)

	switch {
	case strings.Contains(lower, "/satoshi:"):
		return productBitcoinCore
	case strings.Contains(lower, "/bcoin:"):
		return "bcoin_node"
	case strings.Contains(lower, "/btcd:"):
		return "btcd_node"
	case strings.Contains(lower, "/knots:"):
		return "bitcoin_knots"
	case strings.Contains(lower, "/litecoin:"):
		return "litecoin_core"
	case strings.Contains(lower, "/litewallet:"):
		return "litecoin_core"
	}

	return ""
}

// extractBitcoinVersion parses "/Satoshi:25.0.0/" → "25.0.0".
func extractBitcoinVersion(ua string) string {
	idx := strings.IndexByte(ua, ':')
	if idx < 0 {
		return ""
	}

	tail := ua[idx+1:]

	end := len(tail)

	for i, c := range tail {
		if c == '/' || c == '(' || c == ' ' {
			end = i

			break
		}
	}

	if end == 0 {
		return ""
	}

	return tail[:end]
}
