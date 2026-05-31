// Package rtspsnapshot runs a short-lived ffmpeg process to grab one MJPEG
// frame from an RTSP source. Callers must enforce authorization and resource
// limits; this package only performs the subprocess I/O.
package rtspsnapshot

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrTimeout is returned when the capture hits the wall-clock deadline.
var ErrTimeout = errors.New("rtsp snapshot timed out")

// CaptureFailure describes a failed ffmpeg run without exposing RTSP
// credentials from stderr.
type CaptureFailure struct {
	ExitCode   int
	StderrHint string
}

func (e *CaptureFailure) Error() string {
	return "rtsp snapshot capture failed"
}

var rtspURLCredRE = regexp.MustCompile(`(?i)\b(rtsp|rtsps)://[^\s'"]+`)

func sanitizeFFmpegStderr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}

	s = rtspURLCredRE.ReplaceAllString(s, "$1://*redacted*")

	const stderrHintMax = 400

	if len(s) > stderrHintMax {
		return s[:stderrHintMax] + "…"
	}

	return s
}

// Config controls ffmpeg invocation.
type Config struct {
	FFmpegPath  string
	ExecTimeout time.Duration
}

// BuildURL assembles an rtsp:// URL from discrete fields. IPv6-safe.
func BuildURL(ip netip.Addr, port uint16, path, user, password string) (*url.URL, error) {
	if !ip.IsValid() {
		return nil, errors.New("invalid ip")
	}

	if port == 0 {
		return nil, errors.New("invalid port")
	}

	rtspPath := path
	if rtspPath == "" {
		rtspPath = "/"
	}

	if rtspPath[0] != '/' {
		rtspPath = "/" + rtspPath
	}

	pathPart := rtspPath
	rawQuery := ""

	if i := strings.IndexByte(rtspPath, '?'); i >= 0 {
		pathPart = rtspPath[:i]
		if pathPart == "" {
			pathPart = "/"
		}

		rawQuery = rtspPath[i+1:]
	}

	host := net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10))

	u := &url.URL{
		Scheme:   "rtsp",
		Host:     host,
		Path:     pathPart,
		RawQuery: rawQuery,
	}

	if user != "" || password != "" {
		u.User = url.UserPassword(user, password)
	}

	return u, nil
}

// CaptureJPEG runs ffmpeg once and returns one MJPEG frame as JPEG bytes.
// rtspTransport must be "tcp" or "udp" (RTSP over TCP or interleaved/UDP).
func CaptureJPEG(ctx context.Context, cfg Config, source *url.URL, rtspTransport string) ([]byte, error) {
	if cfg.FFmpegPath == "" {
		return nil, errors.New("ffmpeg path is empty")
	}

	if cfg.ExecTimeout <= 0 {
		return nil, errors.New("exec timeout must be positive")
	}

	if source == nil {
		return nil, errors.New("source url is nil")
	}

	if source.Scheme != "rtsp" {
		return nil, errors.New("source must use rtsp scheme")
	}

	t := strings.ToLower(strings.TrimSpace(rtspTransport))
	if t == "" {
		t = "tcp"
	}

	if t != "tcp" && t != "udp" {
		return nil, errors.New("rtsp transport must be tcp or udp")
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.ExecTimeout)
	defer cancel()

	rwTimeoutUS := int64(cfg.ExecTimeout * 9 / 10 / time.Microsecond)
	if rwTimeoutUS < 1_000_000 {
		rwTimeoutUS = 1_000_000
	}

	urlStr := source.String()

	args := []string{
		"-nostdin",
		"-hide_banner",
		"-loglevel", "error",
		"-rw_timeout", strconv.FormatInt(rwTimeoutUS, 10),
		"-rtsp_transport", t,
		"-analyzeduration", "2000000",
		"-probesize", "262144",
		"-i", urlStr,
		"-frames:v", "1",
		"-q:v", "3",
		"-f", "image2pipe",
		"-vcodec", "mjpeg",
		"-",
	}

	cmd := exec.CommandContext(runCtx, cfg.FFmpegPath, args...)

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	stdout, err := cmd.Output()
	if err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrTimeout
		}

		exit := -1

		var exitErr *exec.ExitError

		if errors.As(err, &exitErr) {
			exit = exitErr.ExitCode()
		}

		return nil, &CaptureFailure{
			ExitCode:   exit,
			StderrHint: sanitizeFFmpegStderr(stderr.String()),
		}
	}

	if len(stdout) < 2 {
		return nil, errors.New("ffmpeg produced empty output")
	}

	if stdout[0] != 0xff || stdout[1] != 0xd8 {
		return nil, errors.New("ffmpeg output is not a JPEG")
	}

	return stdout, nil
}
