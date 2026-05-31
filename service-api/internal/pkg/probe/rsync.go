package probe

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const productRsync = "rsync"

var rsyncBannerRE = regexp.MustCompile(`^@RSYNCD:\s*([\d.]+)`)

func init() {
	// 873 — IANA rsync; 4045 — common alternate (openrsync / embedded daemons).
	Register(probeRsync, 873, 4045)
}

// probeRsync reads the rsync daemon greeting line. The wire format is a
// single line `@RSYNCD: <protocol_version>` followed by a module list on
// subsequent reads — we only need the first line for a fingerprint.
func probeRsync(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial rsync target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	buf := make([]byte, 256)

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("can't read rsync greeting: %w", err)
	}

	text := strings.TrimRight(string(buf[:n]), "\r\n")

	if fp := parseRsyncDaemonBanner(text); fp != nil {
		return &Result{
			Target:      target,
			Protocol:    productRsync,
			Banner:      text,
			Fingerprint: fp,
		}, nil
	}

	line := firstLine(text)

	match := rsyncBannerRE.FindStringSubmatch(line)
	if len(match) < 2 {
		return &Result{Target: target, Protocol: protocolTCP, Banner: text}, nil
	}

	version := match[1]

	fp := &FingerprintResult{
		Product: productRsync,
		Version: version,
		RawJSON: mustMarshalJSON(map[string]any{
			"greeting": line,
		}),
	}

	// Drain one more line if the daemon pushes module list immediately.
	_, _ = io.CopyN(io.Discard, conn, 512)

	return &Result{
		Target:      target,
		Protocol:    productRsync,
		Banner:      line,
		Fingerprint: fp,
	}, nil
}

// parseRsyncDaemonBanner recognises the key/value greeting some daemons emit
// on non-standard ports (e.g. 4045): "version: …" and "method: rsync".
func parseRsyncDaemonBanner(text string) *FingerprintResult {
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "method:") || !strings.Contains(lower, "rsync") {
		return nil
	}

	version := ""

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "version:") {
			continue
		}

		version = strings.TrimSpace(strings.TrimPrefix(line, "version:"))

		version = strings.TrimSpace(strings.TrimPrefix(version, "Version:"))
		if fields := strings.Fields(version); len(fields) > 0 {
			version = fields[0]
		}

		break
	}

	return &FingerprintResult{
		Product: productRsync,
		Version: version,
		RawJSON: mustMarshalJSON(map[string]any{"banner": firstLine(text)}),
	}
}
