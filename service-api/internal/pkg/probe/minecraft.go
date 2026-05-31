package probe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
)

const productMinecraftServer = "minecraft_server"

func init() {
	// 25565 — Minecraft Java Edition server default. The Bedrock UDP
	// equivalent (19132) is left out — it speaks RakNet, which our
	// generic UDP path can't easily reach.
	Register(probeMinecraft, 25565)
}

// probeMinecraft performs a Server List Ping handshake (Minecraft Java
// 1.7+) and parses the returned JSON status payload for version + MOTD.
//
// Wire format (https://wiki.vg/Server_List_Ping):
//
//	Handshake packet (state = 1):
//	  varint packet id    = 0x00
//	  varint protocol     = 765 (1.20.4) — any value works; the server
//	                        replies with its own protocol number anyway.
//	  string host         = ""
//	  uint16 port         = 25565
//	  varint next state   = 1 (status)
//	Request packet:
//	  varint packet id    = 0x00 (empty body)
//	Reply:
//	  varint length
//	  varint packet id    = 0x00
//	  string json status payload
func probeMinecraft(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	handshake := buildMinecraftHandshake("", target.Port)
	request := []byte{0x01, 0x00}

	if _, writeErr := conn.Write(append(handshake, request...)); writeErr != nil {
		return nil, writeErr
	}

	length, err := readVarInt(conn)
	if err != nil || length <= 0 || length > 32*1024 {
		return nil, errors.New("minecraft: invalid response length")
	}

	body := make([]byte, length)
	if _, readErr := io.ReadFull(conn, body); readErr != nil {
		return nil, readErr
	}

	if len(body) < 2 || body[0] != 0x00 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	pos := 1

	stringLen, consumed, ok := decodeVarInt(body[pos:])
	if !ok {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	pos += consumed

	if pos+stringLen > len(body) {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	payload := body[pos : pos+stringLen]

	var status struct {
		Version struct {
			Name     string `json:"name"`
			Protocol int    `json:"protocol"`
		} `json:"version"`
		Players struct {
			Online int `json:"online"`
			Max    int `json:"max"`
		} `json:"players"`
		Description any `json:"description"`
	}

	if jsonErr := json.Unmarshal(payload, &status); jsonErr != nil || status.Version.Name == "" {
		return &Result{Target: target, Protocol: protocolTCP, Banner: string(payload)}, nil
	}

	motd := motdString(status.Description)

	fp := &FingerprintResult{
		Product: productMinecraftServer,
		Version: status.Version.Name,
		Edition: motd,
		RawJSON: payload,
	}

	banner := "Minecraft " + status.Version.Name

	if motd != "" {
		banner = banner + " — " + motd
	}

	return &Result{
		Target:      target,
		Protocol:    productMinecraftServer,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// motdString collapses the (legacy text / chat-component object) MOTD
// field into a plain ASCII line.
func motdString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if text, ok := t["text"].(string); ok {
			return text
		}
	}

	return ""
}

// buildMinecraftHandshake constructs the 0x00 handshake packet, length
// prefixed and ready to send.
func buildMinecraftHandshake(host string, port uint16) []byte {
	body := make([]byte, 0, 16+len(host))
	body = append(body, 0x00)
	body = append(body, encodeVarInt(765)...)
	body = append(body, encodeVarInt(len(host))...)
	body = append(body, host...)
	body = append(body, byte(port>>8), byte(port))
	body = append(body, encodeVarInt(1)...)

	return append(encodeVarInt(len(body)), body...)
}

// encodeVarInt serializes a non-negative integer using Minecraft's
// little-endian VarInt encoding.
func encodeVarInt(v int) []byte {
	uv := uint32(v)

	var out []byte

	for {
		b := byte(uv & 0x7F)
		uv >>= 7

		if uv != 0 {
			b |= 0x80
		}

		out = append(out, b)

		if uv == 0 {
			return out
		}
	}
}

// readVarInt reads one Minecraft VarInt from r.
func readVarInt(r io.Reader) (int, error) {
	var (
		result uint32
		shift  uint
		buf    [1]byte
	)

	for range 5 {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}

		result |= uint32(buf[0]&0x7F) << shift

		if buf[0]&0x80 == 0 {
			return int(result), nil
		}

		shift += 7
	}

	return 0, errors.New("minecraft: VarInt too long")
}

// decodeVarInt is the in-memory equivalent of readVarInt for byte slices.
func decodeVarInt(b []byte) (int, int, bool) {
	var (
		result uint32
		shift  uint
	)

	for i := 0; i < len(b) && i < 5; i++ {
		result |= uint32(b[i]&0x7F) << shift

		if b[i]&0x80 == 0 {
			return int(result), i + 1, true
		}

		shift += 7
	}

	return 0, 0, false
}
