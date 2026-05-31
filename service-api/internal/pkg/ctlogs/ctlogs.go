// Package ctlogs queries Certificate Transparency log aggregators for
// certificates associated with a given DNS name.
package ctlogs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Config controls CT log enrichment.
type Config struct {
	Enabled    bool          `env:"CTLOGS_ENABLED"     env-default:"false"`
	BaseURL    string        `env:"CTLOGS_BASE_URL"    env-default:"https://crt.sh"`
	Timeout    time.Duration `env:"CTLOGS_TIMEOUT"     env-default:"15s"`
	Limit      int           `env:"CTLOGS_LIMIT"       env-default:"50"`
	UserAgent  string        `env:"CTLOGS_USER_AGENT"  env-default:"UltraViolet/0.1"`
	MaxRetries int           `env:"CTLOGS_MAX_RETRIES" env-default:"5"`
}

// Entry mirrors one row in the crt.sh JSON output.
type Entry struct {
	CommonName string    `json:"common_name"`
	NameValue  string    `json:"name_value"`
	IssuerName string    `json:"issuer_name"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Serial     string    `json:"serial_number"`
}

// Client looks up CT entries by DNS name.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// New builds a Client.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}

	if cfg.UserAgent == "" {
		cfg.UserAgent = "UltraViolet/0.1"
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// LookupByDomain queries the configured aggregator for all observed certs
// whose CN or SAN matches the supplied domain exactly.
func (c *Client) LookupByDomain(ctx context.Context, domain string) ([]Entry, error) {
	if !c.cfg.Enabled || domain == "" {
		return nil, nil
	}

	return c.fetchEntries(ctx, domain, c.cfg.Limit)
}

func (c *Client) fetchEntries(ctx context.Context, query string, limit int) ([]Entry, error) {
	u, err := url.Parse(c.cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("can't parse crt.sh base URL: %w", err)
	}

	q := u.Query()
	q.Set("q", query)
	q.Set("output", "json")

	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	u.RawQuery = q.Encode()

	body, err := c.do(ctx, u.String())
	if err != nil {
		return nil, err
	}

	var entries []Entry

	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("can't decode crt.sh response: %w", err)
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	return entries, nil
}

const maxResponseBytes = 32 * 1024 * 1024

func (c *Client) do(ctx context.Context, endpoint string) ([]byte, error) {
	var lastErr error

	for attempt := range c.cfg.MaxRetries {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("can't build crt.sh request: %w", err)
		}

		req.Header.Set("User-Agent", c.cfg.UserAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("can't fetch crt.sh: %w", err)

			if !sleepFor(ctx, backoffForAttempt(attempt)) {
				return nil, ctx.Err()
			}

			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()

		if readErr != nil {
			lastErr = fmt.Errorf("can't read crt.sh response: %w", readErr)

			if !sleepFor(ctx, backoffForAttempt(attempt)) {
				return nil, ctx.Err()
			}

			continue
		}

		switch {
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("crt.sh returned %d: %s", resp.StatusCode, snippet(body))

			wait := retryAfterDelay(resp.Header, backoffForAttempt(attempt))
			if !sleepFor(ctx, wait) {
				return nil, ctx.Err()
			}

			continue
		default:
			return nil, fmt.Errorf("crt.sh returned %d: %s", resp.StatusCode, snippet(body))
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("crt.sh: exhausted retries")
}

func backoffForAttempt(attempt int) time.Duration {
	base := time.Duration(1<<attempt) * time.Second
	if base > 30*time.Second {
		base = 30 * time.Second
	}

	jitter := time.Duration(rand.Int64N(int64(base / 2))) //nolint:gosec // jitter only, not a security primitive
	jitter -= base / 4

	return base + jitter
}

func retryAfterDelay(h http.Header, fallback time.Duration) time.Duration {
	raw := h.Get("Retry-After")
	if raw == "" {
		return fallback
	}

	if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}

	if t, err := http.ParseTime(raw); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}

	return fallback
}

func sleepFor(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}

	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func snippet(body []byte) string {
	const limit = 240
	if len(body) > limit {
		return string(body[:limit]) + "…"
	}

	return string(body)
}
