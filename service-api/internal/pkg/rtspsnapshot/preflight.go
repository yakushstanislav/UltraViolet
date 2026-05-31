package rtspsnapshot

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AutoBetweenPathAttempts spaces consecutive auto-path probes to reduce burst
// load on the camera and on uv-api.
const AutoBetweenPathAttempts = 90 * time.Millisecond

const describePreflightTimeout = 2 * time.Second

// DescribePreflight tells whether a JPEG capture attempt is worth running
// after a cheap RTSP DESCRIBE on the same URL.
type DescribePreflight int

const (
	// DescribeTryCapture means DESCRIBE did not prove the path absent; run ffmpeg.
	DescribeTryCapture DescribePreflight = iota
	// DescribeSkipCapture means DESCRIBE indicates this path will not yield a stream.
	DescribeSkipCapture
)

// PreflightDESCRIBE issues a single RTSP DESCRIBE over TCP and returns
// DescribeSkipCapture when the status line clearly indicates that the
// resource path does not exist. On dial/read errors or non-RTSP responses it
// returns DescribeTryCapture so ffmpeg can still decide (many devices only
// answer fully after setup).
func PreflightDESCRIBE(ctx context.Context, u *url.URL) DescribePreflight {
	if u == nil || u.Scheme != "rtsp" {
		return DescribeTryCapture
	}

	pctx, cancel := context.WithTimeout(ctx, describePreflightTimeout)

	defer cancel()

	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(pctx, "tcp", u.Host)
	if err != nil {
		return DescribeTryCapture
	}

	defer func() { _ = conn.Close() }()

	deadline, ok := pctx.Deadline()
	if !ok {
		deadline = time.Now().Add(describePreflightTimeout)
	}

	_ = conn.SetDeadline(deadline)

	req := fmt.Sprintf(
		"DESCRIBE %s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: UltraViolet/0.1\r\nAccept: application/sdp\r\n\r\n",
		u.String(),
	)

	if _, writeErr := conn.Write([]byte(req)); writeErr != nil {
		return DescribeTryCapture
	}

	br := bufio.NewReader(conn)

	statusLine, err := br.ReadString('\n')
	if err != nil {
		return DescribeTryCapture
	}

	statusLine = strings.TrimRight(statusLine, "\r\n")

	if !strings.HasPrefix(statusLine, "RTSP/") {
		return DescribeTryCapture
	}

	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		return DescribeTryCapture
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return DescribeTryCapture
	}

	switch code {
	case 404, 454:
		return DescribeSkipCapture
	default:
		return DescribeTryCapture
	}
}
