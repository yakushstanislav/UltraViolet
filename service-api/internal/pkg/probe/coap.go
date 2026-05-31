package probe

import (
	"context"
	"crypto/rand"
	"errors"
	"regexp"
	"strings"
)

const (
	productCoAP  = "coap"
	productLWM2M = "lwm2m"
)

// coapLinkRE matches one link-format entry from a CoRE Link-Format payload:
//
//	</1/0>;rt="oma.lwm2m";ct=110,<.well-known/core>;ct=40
//
// We pluck the path (group 1) and the optional rt attribute (group 2).
var coapLinkRE = regexp.MustCompile(`<([^>]+)>(?:;[^,]*?rt="([^"]+)")?`)

func init() {
	RegisterUDP(probeCoAP, 5683)
}

// probeCoAP issues a confirmable CoAP GET for `/.well-known/core` (RFC 7252
// + RFC 6690) and parses the link-format payload returned by any CoAP
// server. The response advertises every resource the device exposes, which
// is enough to flag the host as a CoAP endpoint and — when the rt
// attribute is set — narrow the product down (e.g. rt="oma.lwm2m" → OMA
// Lightweight M2M client).
//
// Wire format (RFC 7252, section 3 — Message Format):
//
//	ver/type/tkl  uint8  = 0x40   (ver=1, type=Confirmable, TKL=0)
//	code          uint8  = 0x01   (0.01 GET)
//	message_id    uint16 BE       (random)
//	option 11     uint8           (Uri-Path, delta=11)
//	  length      uint8  = 0x0B   (".well-known" = 11 bytes)
//	  value       []byte = ".well-known"
//	option 11     uint8           (Uri-Path, delta=0)
//	  length      uint8  = 0x04   ("core" = 4 bytes)
//	  value       []byte = "core"
//
// Many CoAP servers reply with a Piggybacked ACK (type=2) carrying the
// link-format payload after a single 0xFF marker. We don't validate the
// CoAP header beyond "first byte starts with the 0x40-0x70 family" — any
// well-formed CoAP message is enough to confirm the protocol.
func probeCoAP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	var midBytes [2]byte

	_, _ = rand.Read(midBytes[:])

	req := []byte{
		0x40, 0x01, // ver=1, type=CON, TKL=0, code=GET
		midBytes[0], midBytes[1], // message ID
		// Uri-Path ".well-known" (option 11, delta=11, length=11)
		0xBB,
		'.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n',
		// Uri-Path "core" (option 11, delta=0, length=4)
		0x04,
		'c', 'o', 'r', 'e',
	}

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil, errors.New("coap: short reply")
	}

	header := buf[0]
	if header>>6 != 1 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	payload := extractCoAPPayload(buf[:n])

	product := productCoAP

	links := coapLinkRE.FindAllStringSubmatch(payload, -1)

	resources := make([]map[string]string, 0, len(links))

	for _, m := range links {
		entry := map[string]string{"path": m[1]}

		if len(m) > 2 && m[2] != "" {
			entry["rt"] = m[2]

			if strings.Contains(strings.ToLower(m[2]), "lwm2m") {
				product = productLWM2M
			}
		}

		resources = append(resources, entry)
	}

	fp := &FingerprintResult{
		Product: product,
		RawJSON: mustMarshalJSON(map[string]any{
			"resources": resources,
			"payload":   payload,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productCoAP,
		Banner:      "CoAP /.well-known/core",
		Fingerprint: fp,
	}, nil
}

// extractCoAPPayload finds the payload marker (0xFF) in a CoAP message and
// returns everything that follows it. Returns "" when no marker is
// present — that's a perfectly valid CoAP reply (e.g. a 4.04 Not Found),
// it just means the device exposed no link-format catalogue.
func extractCoAPPayload(msg []byte) string {
	for i := 4; i < len(msg); i++ {
		if msg[i] == 0xFF {
			return string(msg[i+1:])
		}
	}

	return ""
}
