package probe

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"github.com/spaolacci/murmur3"
)

// shodanFaviconHash computes the Shodan-compatible favicon hash: standard
// base64 encoding with a newline every 76 characters (like Python's
// base64.encodebytes), then MurmurHash3 x86_32 interpreted as signed int32.
func shodanFaviconHash(data []byte) int32 {
	encoded := base64.StdEncoding.EncodeToString(data)

	var sb strings.Builder

	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}

		sb.WriteString(encoded[i:end])
		sb.WriteByte('\n')
	}

	return int32(murmur3.Sum32([]byte(sb.String())))
}

// fetchFaviconHash fetches /favicon.ico relative to baseURL and returns the
// Shodan-compatible hash. Returns (0, false) on any error.
func (s *Stack) fetchFaviconHash(ctx context.Context, baseURL string) (int32, bool) {
	faviconURL := strings.TrimRight(baseURL, "/") + "/favicon.ico"

	timeout := s.cfg.Timeout / 3

	client := &http.Client{
		Transport: s.httpTransport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, faviconURL, nil)
	if err != nil {
		return 0, false
	}

	req.Header.Set("User-Agent", s.cfg.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || len(body) == 0 {
		return 0, false
	}

	return shodanFaviconHash(body), true
}
