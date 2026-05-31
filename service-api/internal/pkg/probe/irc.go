package probe

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const productIRC = "irc"

var ircServerLineRE = regexp.MustCompile(`^:([^\s]+)\s+`)

func init() {
	// Classic IRC daemon ports (EFnet-style + TLS alt).
	// 6668 is intentionally omitted: it is owned by the Tuya LAN-control probe,
	// which has a far more specific fingerprint than IRC's banner sniff.
	Register(probeIRC, 6667, 6669, 6697)
}

// probeIRC waits for the server banner line most IRCds push immediately
// after accept — `:irc.example.net NOTICE * :...` or `:irc.example.net 001
// nick :Welcome`. Any line starting with `:` and a hostname proves IRC.
func probeIRC(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial IRC target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	buf := make([]byte, 512)

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("can't read IRC banner: %w", err)
	}

	line := strings.TrimRight(string(buf[:n]), "\r\n")

	if !strings.HasPrefix(line, ":") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: line}, nil
	}

	host := ""

	if m := ircServerLineRE.FindStringSubmatch(line); len(m) == 2 {
		host = m[1]
	}

	fp := &FingerprintResult{
		Product: productIRC,
		Edition: host,
		RawJSON: mustMarshalJSON(map[string]any{
			"banner": line,
		}),
	}

	_, _ = io.CopyN(io.Discard, conn, 256)

	return &Result{
		Target:      target,
		Protocol:    productIRC,
		Banner:      line,
		Fingerprint: fp,
	}, nil
}
