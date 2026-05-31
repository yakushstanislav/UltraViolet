package probe

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

const productLPD = "lpd"

func init() {
	// 515 — LPD / lpr (RFC 1179). Still common on HP/Lexmark/Xerox MFPs,
	// CUPS legacy bridges and old VPS print servers.
	Register(probeLPD, 515)
}

// probeLPD issues a "Send queue state - short" command for a plausible
// queue name and reads whatever the daemon returns. LPD speaks first only
// after a client command; the response is plain text whose content varies
// per implementation (CUPS, HP-LPD, Microsoft-LPD, etc.), so we look for
// shared markers rather than parse strictly.
func probeLPD(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial LPD target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	// 0x04 = "Send queue state — short". Most LPD implementations either
	// reply with the queue state or an error string mentioning the queue.
	if _, writeErr := conn.Write([]byte("\x04lp\n")); writeErr != nil {
		return nil, fmt.Errorf("can't send LPD short-state command: %w", writeErr)
	}

	buf := make([]byte, 2048)

	n, _ := io.ReadFull(conn, buf)
	if n == 0 {
		extra, _ := conn.Read(buf)
		n = extra
	}

	if n == 0 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	reply := strings.TrimRight(string(buf[:n]), "\x00\r\n ")
	flavour, version := lpdClassify(reply)

	fp := &FingerprintResult{
		Product: productLPD,
		Version: version,
		RawJSON: mustMarshalJSON(map[string]any{
			"flavour": flavour,
			"reply":   reply,
		}),
	}

	if flavour != "" {
		fp.RawJSON = mustMarshalJSON(map[string]any{
			"flavour":   flavour,
			"reply":     reply,
			"queue_arg": "lp",
		})
	}

	return &Result{
		Target:      target,
		Protocol:    productLPD,
		Banner:      reply,
		Fingerprint: fp,
	}, nil
}

// lpdClassify guesses an LPD implementation from its short-state reply.
// CUPS and Microsoft are the two only daemons that include a recognizable
// product token; everything else is generic LPD.
func lpdClassify(reply string) (string, string) {
	low := strings.ToLower(reply)

	switch {
	case strings.Contains(low, "cups"):
		return "cups", lpdExtractVersion(low, "cups/")
	case strings.Contains(low, "microsoft lpd"):
		return "microsoft", ""
	case strings.Contains(low, "hp lpd"), strings.Contains(low, "hewlett"):
		return "hp", ""
	case strings.Contains(low, "lexmark"):
		return "lexmark", ""
	case strings.Contains(low, "xerox"):
		return "xerox", ""
	case strings.Contains(low, "no entries") ||
		strings.Contains(low, "unknown printer") ||
		strings.Contains(low, "is ready and printing"):
		return "generic", ""
	default:
		return "", ""
	}
}

func lpdExtractVersion(low, prefix string) string {
	idx := strings.Index(low, prefix)
	if idx < 0 {
		return ""
	}

	tail := low[idx+len(prefix):]

	end := 0
	for end < len(tail) {
		ch := tail[end]
		if (ch < '0' || ch > '9') && ch != '.' {
			break
		}

		end++
	}

	return tail[:end]
}
