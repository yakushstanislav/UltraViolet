// Package onviflabcred parses ONVIF lab credential pair lists (user:password per line).
package onviflabcred

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// Pair is one username and password candidate for lab credential probing.
type Pair struct {
	User     string
	Password string
}

//go:embed default_credentials.txt
var defaultCredentials []byte

// LoadEmbedded parses the built-in default credential list (trimmed to maxPairs).
func LoadEmbedded(maxPairs int) ([]Pair, error) {
	return ParseLines(bytes.NewReader(defaultCredentials), maxPairs)
}

// LoadFile reads path and parses credential lines (trimmed to maxPairs).
func LoadFile(path string, maxPairs int) ([]Pair, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("can't read ONVIF lab credentials file: %w", err)
	}

	return ParseLines(bytes.NewReader(raw), maxPairs)
}

// ParseLines reads user:password lines (first ':' separates). Lines starting with
// '#' after optional BOM/whitespace are comments. Empty lines are skipped.
// Pairs are de-duplicated in file order; at most maxPairs entries are returned.
func ParseLines(r io.Reader, maxPairs int) ([]Pair, error) {
	if maxPairs < 1 {
		return nil, errors.New("maxPairs must be at least 1")
	}

	sc := bufio.NewScanner(r)
	// Longest line in default file is short; allow generous scan for custom files.
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)

	seen := make(map[string]struct{}, maxPairs)
	out := make([]Pair, 0, maxPairs)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimPrefix(line, "\ufeff")
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		user, pass, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line has no ':' separator: %q", truncateRunes(line, 80))
		}

		user = strings.TrimSpace(user)
		pass = strings.TrimSpace(pass)

		if user == "" || pass == "" {
			return nil, fmt.Errorf("empty user or password after trim: %q", truncateRunes(line, 80))
		}

		if strings.ContainsAny(user, "\r\n\x00") || strings.ContainsAny(pass, "\r\n\x00") {
			return nil, fmt.Errorf("user or password contains invalid characters: %q", truncateRunes(line, 80))
		}

		key := user + "\x00" + pass
		if _, dup := seen[key]; dup {
			continue
		}

		seen[key] = struct{}{}

		out = append(out, Pair{User: user, Password: pass})

		if len(out) >= maxPairs {
			break
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("can't scan ONVIF lab credentials: %w", err)
	}

	return out, nil
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes < 1 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}

	runes := []rune(s)

	return string(runes[:maxRunes]) + "…"
}
