package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

const productIdent = "ident"

func init() {
	Register(probeIdent, 113)
}

// probeIdent sends the RFC 1413 query "0 , 0" and parses the USERID reply.
func probeIdent(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial ident target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	if _, writeErr := io.WriteString(conn, "0 , 0\r\n"); writeErr != nil {
		return nil, fmt.Errorf("can't send ident query: %w", writeErr)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	fp := &FingerprintResult{
		Product: productIdent,
		RawJSON: mustMarshalJSON(map[string]any{"reply": line}),
	}

	return &Result{
		Target:      target,
		Protocol:    productIdent,
		Banner:      line,
		Fingerprint: fp,
	}, nil
}
