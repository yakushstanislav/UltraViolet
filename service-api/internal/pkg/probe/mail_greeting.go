package probe

import (
	"bufio"
	"context"
	"fmt"
	"strings"
)

func init() {
	// Alternate mail ports that push a POP3/IMAP greeting (e.g. Dovecot on 5357).
	Register(probeMailGreeting, 5357)
}

// probeMailGreeting reads the server line and dispatches to POP3 or IMAP
// probing when the greeting matches.
func probeMailGreeting(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial mail greeting target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("can't read mail greeting: %w", err)
	}

	banner := strings.TrimRight(greeting, "\r\n")

	switch {
	case strings.HasPrefix(banner, "+OK"):
		return finishPOP3Probe(target, conn, reader, banner)
	case strings.HasPrefix(banner, "*"):
		return finishIMAPProbe(target, conn, reader, banner)
	default:
		return &Result{Target: target, Protocol: protocolTCP, Banner: banner}, nil
	}
}
