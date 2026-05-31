package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

func init() {
	Register(probePOP3, 110, 995)
	Register(probeIMAP, 143, 993)
}

// probePOP3 reads the POP3 greeting and CAPA list, including STLS detection.
func probePOP3(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial POP3 target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("can't read POP3 greeting: %w", err)
	}

	banner := strings.TrimRight(greeting, "\r\n")

	return finishPOP3Probe(target, conn, reader, banner)
}

func finishPOP3Probe(target Target, conn io.Writer, reader *bufio.Reader, banner string) (*Result, error) {
	result := &Result{
		Target:   target,
		Protocol: "pop3",
		Banner:   banner,
	}

	if !strings.HasPrefix(banner, "+OK") {
		return result, nil
	}

	_, _ = fmt.Fprint(conn, "CAPA\r\n")

	caps := popReadDotResponse(reader)

	stls := false
	saslMethods := []string{}

	for _, line := range caps {
		upper := strings.ToUpper(strings.TrimSpace(line))

		switch {
		case upper == "STLS":
			stls = true
		case strings.HasPrefix(upper, "SASL "):
			saslMethods = strings.Fields(strings.TrimPrefix(upper, "SASL "))
		}
	}

	result.Fingerprint = &FingerprintResult{
		Product:     "pop3",
		TLSRequired: boolPtr(stls),
		RawJSON: mustMarshalJSON(map[string]any{
			"banner":       banner,
			"capabilities": caps,
			"stls":         stls,
			"sasl":         saslMethods,
		}),
	}

	return result, nil
}

// probeIMAP reads the IMAP greeting and CAPABILITY response.
func probeIMAP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial IMAP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("can't read IMAP greeting: %w", err)
	}

	banner := strings.TrimRight(greeting, "\r\n")

	return finishIMAPProbe(target, conn, reader, banner)
}

func finishIMAPProbe(target Target, conn io.Writer, reader *bufio.Reader, banner string) (*Result, error) {
	result := &Result{
		Target:   target,
		Protocol: "imap",
		Banner:   banner,
	}

	if !strings.HasPrefix(banner, "*") {
		return result, nil
	}

	_, _ = fmt.Fprint(conn, "a01 CAPABILITY\r\n")

	caps := imapReadTaggedResponse(reader, "a01")

	starttls := false
	loginDisabled := false
	saslMethods := []string{}
	identity := strings.ToUpper(strings.Join(caps, " "))

	for _, line := range caps {
		upper := strings.ToUpper(line)

		if strings.HasPrefix(upper, "* CAPABILITY") {
			fields := strings.Fields(strings.TrimPrefix(upper, "* CAPABILITY"))

			for _, token := range fields {
				switch {
				case token == "STARTTLS":
					starttls = true
				case token == "LOGINDISABLED":
					loginDisabled = true
				case strings.HasPrefix(token, "AUTH="):
					saslMethods = append(saslMethods, strings.TrimPrefix(token, "AUTH="))
				}
			}
		}
	}

	result.Fingerprint = &FingerprintResult{
		Product:     "imap",
		TLSRequired: boolPtr(starttls),
		RawJSON: mustMarshalJSON(map[string]any{
			"banner":         banner,
			"capabilities":   caps,
			"starttls":       starttls,
			"login_disabled": loginDisabled,
			"sasl":           saslMethods,
			"identity":       identity,
		}),
	}

	return result, nil
}

// popReadDotResponse reads multi-line CAPA output terminated by a dot line.
func popReadDotResponse(reader *bufio.Reader) []string {
	var out []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return out
		}

		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			return out
		}

		out = append(out, trimmed)
	}
}

// imapReadTaggedResponse reads response lines until the line begins with
// the supplied tag (e.g. "a01 OK").
func imapReadTaggedResponse(reader *bufio.Reader, tag string) []string {
	var out []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return out
		}

		trimmed := strings.TrimRight(line, "\r\n")
		out = append(out, trimmed)

		if strings.HasPrefix(trimmed, tag+" ") {
			return out
		}
	}
}
