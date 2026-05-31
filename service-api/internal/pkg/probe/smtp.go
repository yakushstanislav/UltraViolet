package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func init() {
	Register(probeSMTP, 25, 587, 2525)
	Register(probeSMTPS, 465)
}

// probeSMTPS wraps the SMTP probe in implicit TLS (Submission over SSL).
func probeSMTPS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	rawConn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial SMTPS target: %w", err)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         target.IP.String(),
		InsecureSkipVerify: true, //nolint:gosec // scanner probes arbitrary hosts
	})

	if handshakeErr := tlsConn.HandshakeContext(ctx); handshakeErr != nil {
		_ = rawConn.Close()

		return nil, fmt.Errorf("can't TLS handshake SMTPS: %w", handshakeErr)
	}

	defer func() { _ = tlsConn.Close() }()

	result, err := smtpReadEHLO(tlsConn, target)
	if err != nil {
		return nil, err
	}

	result.Protocol = "smtps"

	if result.SMTP != nil {
		result.SMTP.STARTTLS = true
	}

	return result, nil
}

// smtpReadEHLO runs the greeting + EHLO conversation over an existing
// connection. Used by both the cleartext SMTP probe and SMTPS implicit TLS.
func smtpReadEHLO(conn net.Conn, target Target) (*Result, error) {
	r := bufio.NewReader(conn)

	greetingLines, err := smtpReadResponse(r)
	if err != nil || len(greetingLines) == 0 {
		return nil, fmt.Errorf("can't read SMTP greeting: %w", err)
	}

	banner := strings.TrimSpace(greetingLines[0])

	result := &Result{
		Target:   target,
		Protocol: "smtp",
		Banner:   banner,
	}

	if len(banner) < 3 || banner[:3] != "220" {
		return result, nil
	}

	if _, writeErr := fmt.Fprintf(conn, "EHLO ultraviolet\r\n"); writeErr != nil {
		return result, nil //nolint:nilerr // partial success — banner captured even if EHLO failed
	}

	ehloLines, ehloErr := smtpReadResponse(r)
	if ehloErr != nil || len(ehloLines) == 0 {
		return result, nil //nolint:nilerr // partial success — banner captured even if EHLO unanswered
	}

	if len(ehloLines[0]) < 3 || ehloLines[0][:3] != "250" {
		return result, nil
	}

	caps := smtpParseCapabilities(ehloLines)

	smtpInfo := &SMTPResult{
		Banner:       banner,
		Capabilities: caps,
	}

	for _, cap := range caps {
		upper := strings.ToUpper(cap)

		if upper == "STARTTLS" {
			smtpInfo.STARTTLS = true

			continue
		}

		if strings.HasPrefix(upper, "AUTH ") {
			smtpInfo.AuthMethods = strings.Fields(cap[5:])

			continue
		}

		if strings.HasPrefix(upper, "SIZE") {
			rest := strings.TrimSpace(cap[4:])

			if n, parseErr := strconv.ParseInt(rest, 10, 64); parseErr == nil {
				smtpInfo.MaxMessageSize = n
			}
		}
	}

	result.SMTP = smtpInfo

	return result, nil
}

// probeSMTP connects to the target, reads the server greeting, sends EHLO,
// and parses the capability list (STARTTLS, AUTH methods, SIZE).
func probeSMTP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial SMTP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	return smtpReadEHLO(conn, target)
}

// smtpReadResponse reads one complete SMTP response (single-line or multi-line)
// and returns all lines including their code prefix.
func smtpReadResponse(r *bufio.Reader) ([]string, error) {
	var lines []string

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return lines, err
		}

		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)

		if len(line) < 4 || line[3] != '-' {
			break
		}
	}

	return lines, nil
}

// smtpParseCapabilities extracts capability strings from EHLO response lines,
// skipping the first line which contains the domain name.
func smtpParseCapabilities(lines []string) []string {
	caps := make([]string, 0, len(lines))

	for _, line := range lines[1:] {
		if len(line) < 4 {
			continue
		}

		capStr := strings.TrimSpace(line[4:])
		if capStr != "" {
			caps = append(caps, capStr)
		}
	}

	return caps
}
