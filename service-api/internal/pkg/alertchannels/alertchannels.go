// Package alertchannels delivers alert notifications to external destinations.
// Only the generic JSON webhook channel is supported; other channels can be
// added behind the same dispatcher interface later.
package alertchannels

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ErrUnsafeWebhookURL is returned when a webhook destination resolves to a
// loopback, private, link-local, or otherwise non-routable address. The check
// runs both on the literal URL host and on every resolved IP so a malicious
// hostname can not be used to bypass the filter.
var ErrUnsafeWebhookURL = errors.New("webhook destination is not allowed")

// Notification is the payload delivered to one channel.
type Notification struct {
	RuleID   uint64
	RuleName string
	Hits     int
	Query    map[string]any
}

// Dispatcher routes a Notification to its concrete channel.
type Dispatcher struct {
	httpClient *http.Client
	resolver   *net.Resolver
}

// New builds a Dispatcher with a sane default HTTP client.
func New() *Dispatcher {
	return &Dispatcher{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		resolver:   net.DefaultResolver,
	}
}

// Send routes the notification according to the channel name. Empty channel
// or "log" channels are no-ops handled by the caller's logger.
func (d *Dispatcher) Send(ctx context.Context, channel, destination string, n Notification) error {
	if destination == "" {
		return nil
	}

	if strings.EqualFold(channel, "webhook") {
		return d.sendWebhook(ctx, destination, n)
	}

	return nil
}

func (d *Dispatcher) sendWebhook(ctx context.Context, urlStr string, n Notification) error {
	if err := d.validateWebhookURL(ctx, urlStr); err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]any{
		"rule_id":   n.RuleID,
		"rule_name": n.RuleName,
		"hits":      n.Hits,
		"query":     n.Query,
		"fired_at":  time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("can't marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("can't build webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "UltraViolet/0.1")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("can't post webhook: %w", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	return nil
}

// validateWebhookURL rejects URLs whose scheme is not http/https and whose
// host resolves to a loopback, link-local, private, multicast, or
// unspecified address. The DNS resolution is best-effort: a hostname that
// fails to resolve at validation time still fails later in http.Do, so this
// check is purely defensive.
func (d *Dispatcher) validateWebhookURL(ctx context.Context, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrUnsafeWebhookURL)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("scheme must be http or https: %w", ErrUnsafeWebhookURL)
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("host is empty: %w", ErrUnsafeWebhookURL)
	}

	if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !isPublicAddr(addr) {
			return fmt.Errorf("host resolves to a non-public address: %w", ErrUnsafeWebhookURL)
		}

		return nil
	}

	resolved, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("can't resolve host: %w", ErrUnsafeWebhookURL)
	}

	if len(resolved) == 0 {
		return fmt.Errorf("host resolved to no addresses: %w", ErrUnsafeWebhookURL)
	}

	for _, addr := range resolved {
		if !isPublicAddr(addr) {
			return fmt.Errorf("host resolves to a non-public address: %w", ErrUnsafeWebhookURL)
		}
	}

	return nil
}

// isPublicAddr reports whether addr is routable on the public internet.
// Loopback, private (RFC 1918 / ULA), link-local, multicast, unspecified,
// and IPv4-mapped variants are all rejected.
func isPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() ||
		addr.IsInterfaceLocalMulticast() {
		return false
	}

	return true
}
