package probe

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const productRTSP = "rtsp"

func init() {
	Register(probeRTSP, 554, 8554)
}

// probeRTSP issues an RTSP OPTIONS request and parses the status line plus
// Server / Public headers to fingerprint the responder. When the peer opens
// with a TLS record (common on 554/8554) we hand off to probeHTTPS.
func probeRTSP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial RTSP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	timeout := s.probeTimeout(ctx)

	peek := make([]byte, 8)

	_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))

	n, _ := conn.Read(peek)

	_ = conn.SetDeadline(deadlineFromCtx(ctx, timeout))

	if n > 0 && looksLikeTLSHandshakeRecord(peek[:n]) {
		_ = conn.Close()

		return probeHTTPS(ctx, s, target)
	}

	request := fmt.Sprintf(
		"OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: %s\r\n\r\n",
		target.IP.String(), target.Port, s.cfg.UserAgent,
	)

	if _, writeErr := conn.Write([]byte(request)); writeErr != nil {
		return nil, fmt.Errorf("can't send RTSP OPTIONS: %w", writeErr)
	}

	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(peek[:n]), conn))

	statusLine, err := reader.ReadString('\n')
	if err != nil && statusLine == "" {
		if n > 0 && strings.HasPrefix(string(peek[:n]), "HTTP/") {
			_ = conn.Close()

			return probeHTTPS(ctx, s, target)
		}

		return nil, fmt.Errorf("can't read RTSP status line: %w", err)
	}

	statusLine = strings.TrimRight(statusLine, "\r\n")

	if !strings.HasPrefix(statusLine, "RTSP/") {
		if strings.HasPrefix(statusLine, "HTTP/") {
			_ = conn.Close()

			return probeHTTPS(ctx, s, target)
		}

		return &Result{
			Target:   target,
			Protocol: protocolTCP,
			Banner:   statusLine,
		}, nil
	}

	headers := readRTSPHeaders(reader)

	statusCode := parseRTSPStatusCode(statusLine)
	server := headers["server"]
	public := headers["public"]
	cseq := headers["cseq"]

	banner := statusLine
	if server != "" {
		banner = statusLine + " | Server: " + server
	}

	fp := &FingerprintResult{
		Product: productRTSP,
		Version: server,
		RawJSON: mustMarshalJSON(map[string]any{
			"status_line": statusLine,
			"status_code": statusCode,
			"server":      server,
			"public":      public,
			"cseq":        cseq,
		}),
	}

	if statusCode == 401 {
		authRequired := true
		fp.AuthRequired = &authRequired
	} else if statusCode > 0 {
		authRequired := false
		fp.AuthRequired = &authRequired
		fp.Anonymous = true
	}

	return &Result{
		Target:      target,
		Protocol:    productRTSP,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// readRTSPHeaders consumes header lines until a blank line or EOF and returns
// a lower-cased key map. Duplicate headers are joined with ", " to match the
// HTTP convention.
func readRTSPHeaders(reader *bufio.Reader) map[string]string {
	headers := make(map[string]string, 8)

	for range 64 {
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			break
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}

		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])

		if existing, ok := headers[key]; ok {
			headers[key] = existing + ", " + value
		} else {
			headers[key] = value
		}
	}

	return headers
}

// parseRTSPStatusCode extracts the numeric status code from an "RTSP/1.0 NNN
// Reason" line. Returns 0 when the line does not match the expected shape.
func parseRTSPStatusCode(statusLine string) int {
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}

	return code
}
