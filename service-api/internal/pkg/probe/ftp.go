package probe

import (
	"bufio"
	"context"
	"fmt"
	"strings"
)

const productFTP = "ftp"

func init() {
	Register(probeFTP, 21)
}

// probeFTP reads the FTP greeting, attempts SYST, FEAT and an anonymous
// login probe to capture server identification and authentication posture.
func probeFTP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial FTP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)

	greeting, err := ftpReadResponse(reader)
	if err != nil || greeting == "" {
		return nil, fmt.Errorf("can't read FTP greeting: %w", err)
	}

	banner := firstLine(greeting)

	result := &Result{
		Target:   target,
		Protocol: productFTP,
		Banner:   banner,
	}

	syst, _ := ftpCommand(conn, reader, "SYST\r\n")
	feat, _ := ftpCommand(conn, reader, "FEAT\r\n")

	authAnonymous := false

	if userResp, err := ftpCommand(conn, reader, "USER anonymous\r\n"); err == nil {
		if strings.HasPrefix(userResp, "230 ") {
			authAnonymous = true
		} else if strings.HasPrefix(userResp, "331 ") {
			if passResp, perr := ftpCommand(conn, reader, "PASS anonymous@example.com\r\n"); perr == nil {
				if strings.HasPrefix(passResp, "230 ") {
					authAnonymous = true
				}
			}
		}
	}

	tlsAvailable := strings.Contains(strings.ToUpper(feat), "AUTH TLS") ||
		strings.Contains(strings.ToUpper(feat), "AUTH SSL")

	authRequired := !authAnonymous

	fp := &FingerprintResult{
		Product:      productFTP,
		Version:      ftpServerVersion(banner),
		Anonymous:    authAnonymous,
		AuthRequired: &authRequired,
		TLSRequired:  boolPtr(tlsAvailable),
		RawJSON: mustMarshalJSON(map[string]any{
			"banner":         banner,
			"syst":           strings.TrimSpace(syst),
			"feat":           strings.TrimSpace(feat),
			"auth_anonymous": authAnonymous,
			"tls_available":  tlsAvailable,
		}),
	}

	result.Fingerprint = fp

	return result, nil
}

// ftpReadResponse reads one (possibly multi-line) FTP response.
func ftpReadResponse(reader *bufio.Reader) (string, error) {
	var (
		first string
		buf   strings.Builder
	)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return buf.String(), err
		}

		buf.WriteString(line)

		trimmed := strings.TrimRight(line, "\r\n")
		if len(trimmed) < 3 {
			return buf.String(), nil
		}

		if first == "" {
			first = trimmed
		}

		if len(trimmed) >= 4 && trimmed[3] == '-' {
			continue
		}

		return buf.String(), nil
	}
}

type writerOnly interface {
	Write(p []byte) (int, error)
}

// ftpCommand writes one command line and returns the response.
func ftpCommand(conn writerOnly, reader *bufio.Reader, cmd string) (string, error) {
	if _, err := fmt.Fprint(conn, cmd); err != nil {
		return "", err
	}

	return ftpReadResponse(reader)
}

// ftpServerVersion extracts a server label from the 220 greeting line when
// it follows the common "220 product version ready" pattern.
func ftpServerVersion(banner string) string {
	if len(banner) < 4 || banner[:4] != "220 " {
		return ""
	}

	rest := strings.TrimSpace(banner[4:])

	parts := strings.Fields(rest)
	if len(parts) < 2 {
		return rest
	}

	return strings.Join(parts[:2], " ")
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}

	return s
}

func boolPtr(v bool) *bool {
	return &v
}
