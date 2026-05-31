package probe

import (
	"context"
	"fmt"
	"strings"
)

func init() {
	Register(probeTelnet, 23)
}

// probeTelnet reads the initial bytes from a telnet port. The IAC option
// negotiation prefix (0xff) is stripped to expose any printable banner
// that follows.
func probeTelnet(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial telnet target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	buf := make([]byte, maxBannerBytes)

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return &Result{Target: target, Protocol: "telnet"}, nil
	}

	raw := buf[:n]

	negotiation := telnetExtractOptions(raw)
	banner := telnetStripIAC(raw)

	return &Result{
		Target:   target,
		Protocol: "telnet",
		Banner:   strings.TrimRight(banner, "\r\n\x00"),
		Fingerprint: &FingerprintResult{
			Product: "telnet",
			RawJSON: mustMarshalJSON(map[string]any{
				"banner":      banner,
				"negotiation": negotiation,
			}),
		},
	}, nil
}

// telnetStripIAC removes IAC negotiation sequences (0xff followed by 1 or 2
// bytes) and returns the remaining printable banner string.
func telnetStripIAC(raw []byte) string {
	out := make([]byte, 0, len(raw))

	for i := 0; i < len(raw); i++ {
		if raw[i] != 0xff {
			out = append(out, raw[i])

			continue
		}

		if i+1 >= len(raw) {
			break
		}

		cmd := raw[i+1]

		switch cmd {
		case 0xfb, 0xfc, 0xfd, 0xfe:
			i += 2
		case 0xfa:
			for i+1 < len(raw) && (raw[i] != 0xff || raw[i+1] != 0xf0) {
				i++
			}

			if i+1 < len(raw) {
				i++
			}
		default:
			i++
		}
	}

	return string(out)
}

// telnetExtractOptions returns a coarse list of negotiated options seen in
// the IAC stream, e.g. "WILL ECHO".
func telnetExtractOptions(raw []byte) []string {
	var options []string

	verbs := map[byte]string{0xfb: "WILL", 0xfc: "WONT", 0xfd: "DO", 0xfe: "DONT"}

	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != 0xff {
			continue
		}

		verb, ok := verbs[raw[i+1]]
		if !ok {
			continue
		}

		options = append(options, verb+" "+telnetOptionName(raw[i+2]))
	}

	return options
}

func telnetOptionName(code byte) string {
	switch code {
	case 1:
		return "ECHO"
	case 3:
		return "SGA"
	case 5:
		return "STATUS"
	case 24:
		return "TERM_TYPE"
	case 31:
		return "NAWS"
	case 32:
		return "TERM_SPEED"
	case 33:
		return "FLOW"
	case 34:
		return "LINEMODE"
	case 35:
		return "X_DISPLAY"
	case 36:
		return "ENV"
	case 39:
		return "NEW_ENV"
	}

	return "OPT_" + telnetByteHex(code)
}

func telnetByteHex(b byte) string {
	const hex = "0123456789abcdef"

	return string([]byte{hex[b>>4], hex[b&0x0f]})
}
