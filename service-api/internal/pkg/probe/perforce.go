package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

const productPerforce = "perforce_p4d"

func init() {
	// 1666 — Perforce P4D (Helix Core) server. Default in every
	// distribution, occasionally moved to 1667/1818 in HA setups.
	Register(probePerforce, 1666)
}

// probePerforce sends a minimal RPC frame asking for "protocol" — the
// first request a real p4 client emits. P4D answers with a single RPC
// frame containing key/value pairs like "server2=46", "revver=2024.1"
// and "serverID=...". We don't parse the full key list; locating the
// "server2" marker is enough for a confident fingerprint, and the
// remainder is preserved in RawJSON for diagnostics.
//
// Wire format (P4 RPC, all little-endian):
//
//	uint8   checksum    (XOR-fold of length bytes; ignored on input)
//	uint32  length      (total payload bytes following this header)
//	[ "func\x00<verb>\x00" + zero or more "k\x00v\x00" pairs ]
//
// Each payload entry is itself "key\x00\x00\x00\x00length\x00value\x00",
// where the inner uint32 is the value length. For an empty argument list
// (which is what `protocol` accepts) the entire payload reduces to the
// single key/value pair "func\x00\x00\x00\x00\x08\x00protocol\x00".
func probePerforce(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial Perforce target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	if _, writeErr := conn.Write(perforceProtocolRequest()); writeErr != nil {
		return nil, fmt.Errorf("can't send P4 protocol request: %w", writeErr)
	}

	header := make([]byte, 5)
	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	length := binary.LittleEndian.Uint32(header[1:5])
	if length == 0 || length > 1<<20 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	body := make([]byte, length)
	if _, readErr := io.ReadFull(conn, body); readErr != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	if !perforceLooksLikeReply(body) {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	keys := perforceExtractStrings(body)

	fp := &FingerprintResult{
		Product: productPerforce,
		Version: perforcePickVersion(keys),
		RawJSON: mustMarshalJSON(map[string]any{
			"tokens": keys,
		}),
	}

	banner := "Perforce P4D"
	if version := fp.Version; version != "" {
		banner = "Perforce P4D " + version
	}

	return &Result{
		Target:      target,
		Protocol:    productPerforce,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

func perforceProtocolRequest() []byte {
	const (
		funcKey  = "func\x00"
		funcVal  = "protocol\x00"
		valueLen = uint32(len(funcVal))
	)

	payload := make([]byte, 0, len(funcKey)+4+len(funcVal))
	payload = append(payload, funcKey...)
	payload = binary.LittleEndian.AppendUint32(payload, valueLen)
	payload = append(payload, funcVal...)

	out := make([]byte, 0, 5+len(payload))
	out = append(out, 0x00) // checksum (ignored on read by p4d)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	out = append(out, payload...)

	return out
}

// perforceLooksLikeReply tests for the well-known protocol keys present in
// any P4D ≥ 2010.x reply. We accept either "server2" (Helix Core ≥ 2013)
// or the older "server" plus "revver" combo to avoid false negatives.
func perforceLooksLikeReply(body []byte) bool {
	asString := string(body)

	if strings.Contains(asString, "server2") {
		return true
	}

	return strings.Contains(asString, "server") && strings.Contains(asString, "revver")
}

// perforceExtractStrings returns every printable token at least 2 chars
// long. Good enough to surface keys (server2, revver, serverID, etc.) and
// their string values without writing a full P4 RPC parser.
func perforceExtractStrings(body []byte) []string {
	out := make([]string, 0, 16)

	start := -1

	for i, b := range body {
		switch {
		case b >= 0x20 && b < 0x7F:
			if start < 0 {
				start = i
			}
		default:
			if start >= 0 && i-start >= 2 {
				out = append(out, string(body[start:i]))
			}

			start = -1
		}
	}

	if start >= 0 && len(body)-start >= 2 {
		out = append(out, string(body[start:]))
	}

	return out
}

// perforcePickVersion scans the extracted tokens for the "release" or
// "revver" payload, both of which carry the public release identifier
// (e.g. "2024.1/2536045"). We strip the build counter so the version is
// usable for CVE matching against the cpe:2.3:a:perforce:helix_core
// applicability records.
func perforcePickVersion(tokens []string) string {
	for i, tok := range tokens {
		low := strings.ToLower(tok)

		if (low == "release" || low == "release2" || low == "revver") && i+1 < len(tokens) {
			value := tokens[i+1]
			if idx := strings.Index(value, "/"); idx > 0 {
				value = value[:idx]
			}

			return value
		}
	}

	return ""
}
