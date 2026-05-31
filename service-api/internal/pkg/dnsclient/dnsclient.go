// Package dnsclient is the shared low-level resolver used by both the forward
// and reverse DNS enrichment passes. Queries go through github.com/miekg/dns
// against a round-robin resolver pool with retries, EDNS0, TCP fallback on
// truncation, and an optional in-process TTL cache — so the scanner never
// depends on the host's /etc/resolv.conf.
package dnsclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Outcome classifies the terminal result of a Query call. It is handed to the
// optional Observer so callers can record metrics with their own direction
// label without dnsclient depending on a metrics package.
const (
	OutcomeSuccess  = "success"
	OutcomeNXDomain = "nxdomain"
	OutcomeTimeout  = "timeout"
	OutcomeError    = "error"
)

// Observer is invoked once per Query with the queried type, the classified
// outcome, and the wall-clock duration. nil disables observation.
type Observer func(qtype uint16, outcome string, dur time.Duration)

// Config controls a Client. Resolvers is the round-robin pool as host:port
// (bare IPs default to :53). CacheTTL of 0 disables the in-process cache.
type Config struct {
	Resolvers       []string
	PerQueryTimeout time.Duration
	Retries         int
	CacheTTL        time.Duration
	Observer        Observer
}

type cacheEntry struct {
	msg    *dns.Msg
	expiry time.Time
}

// Client issues retrying DNS queries against a fixed resolver pool. It is safe
// for concurrent use by multiple goroutines.
type Client struct {
	resolvers       []string
	udp             *dns.Client
	tcp             *dns.Client
	perQueryTimeout time.Duration
	retries         int
	observer        Observer

	rr atomic.Uint64

	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]cacheEntry
}

// New normalizes the resolver pool and builds a ready Client. It errors when
// no usable resolver remains after normalization.
func New(cfg Config) (*Client, error) {
	resolvers := make([]string, 0, len(cfg.Resolvers))

	for _, raw := range cfg.Resolvers {
		addr := strings.TrimSpace(raw)
		if addr == "" {
			continue
		}

		if _, _, err := net.SplitHostPort(addr); err != nil {
			// Bare IP supplied — default to port 53.
			addr = net.JoinHostPort(addr, "53")
		}

		resolvers = append(resolvers, addr)
	}

	if len(resolvers) == 0 {
		return nil, errors.New("dnsclient: no usable resolvers configured")
	}

	perQueryTimeout := cfg.PerQueryTimeout
	if perQueryTimeout <= 0 {
		perQueryTimeout = 3 * time.Second
	}

	c := &Client{
		resolvers:       resolvers,
		udp:             &dns.Client{Net: "udp", Timeout: perQueryTimeout},
		tcp:             &dns.Client{Net: "tcp", Timeout: perQueryTimeout},
		perQueryTimeout: perQueryTimeout,
		retries:         cfg.Retries,
		observer:        cfg.Observer,
		cacheTTL:        cfg.CacheTTL,
	}

	if cfg.CacheTTL > 0 {
		c.cache = make(map[string]cacheEntry)
	}

	return c, nil
}

// Query resolves fqdn for qtype against the resolver pool. It retries transient
// failures (timeout, IO error, SERVFAIL) on the next resolver up to Retries+1
// total attempts, falls back to TCP on a truncated answer, and serves cached
// answers within their TTL. NXDOMAIN/REFUSED are returned without retry — they
// are authoritative. A nil error guarantees a non-nil *dns.Msg.
func (c *Client) Query(ctx context.Context, fqdn string, qtype uint16) (*dns.Msg, error) {
	start := time.Now()

	if cached, ok := c.cacheGet(fqdn, qtype); ok {
		c.observe(qtype, classify(cached, nil), time.Since(start))

		return cached, nil
	}

	resp, err := c.queryWithRetry(ctx, fqdn, qtype)

	c.observe(qtype, classify(resp, err), time.Since(start))

	if err == nil && resp != nil {
		c.cacheSet(fqdn, qtype, resp)
	}

	return resp, err
}

func (c *Client) queryWithRetry(ctx context.Context, fqdn string, qtype uint16) (*dns.Msg, error) {
	attempts := c.retries + 1
	if attempts < 1 {
		attempts = 1
	}

	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, false)

	var lastErr error

	for range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		idx := int(c.rr.Add(1)-1) % len(c.resolvers)
		resolver := c.resolvers[idx]

		resp, _, err := c.udp.ExchangeContext(ctx, msg, resolver)
		if err != nil {
			lastErr = fmt.Errorf("resolver %s: %w", resolver, err)

			continue
		}

		if resp == nil {
			lastErr = fmt.Errorf("resolver %s: nil response", resolver)

			continue
		}

		if resp.Truncated {
			// EDNS0 advertised 4096 but the answer still didn't fit UDP —
			// retry the same resolver over TCP to recover the full record set.
			if tcpResp, _, terr := c.tcp.ExchangeContext(ctx, msg, resolver); terr == nil && tcpResp != nil {
				resp = tcpResp
			}
		}

		if resp.Rcode == dns.RcodeServerFailure {
			lastErr = fmt.Errorf("resolver %s: SERVFAIL", resolver)

			continue
		}

		return resp, nil
	}

	return nil, lastErr
}

func (c *Client) observe(qtype uint16, outcome string, dur time.Duration) {
	if c.observer != nil {
		c.observer(qtype, outcome, dur)
	}
}

func (c *Client) cacheGet(fqdn string, qtype uint16) (*dns.Msg, bool) {
	if c.cache == nil {
		return nil, false
	}

	key := cacheKey(fqdn, qtype)

	c.mu.RLock()
	entry, ok := c.cache[key]
	c.mu.RUnlock()

	if !ok || time.Now().After(entry.expiry) {
		return nil, false
	}

	return entry.msg, true
}

func (c *Client) cacheSet(fqdn string, qtype uint16, msg *dns.Msg) {
	if c.cache == nil {
		return
	}

	// Only cache answers we trust to be stable: NOERROR and NXDOMAIN. The TTL
	// is the smaller of the configured ceiling and the answer's minimum RR TTL.
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}

	ttl := c.cacheTTL

	if rrTTL := minTTL(msg); rrTTL > 0 && rrTTL < ttl {
		ttl = rrTTL
	}

	key := cacheKey(fqdn, qtype)

	c.mu.Lock()
	c.cache[key] = cacheEntry{msg: msg, expiry: time.Now().Add(ttl)}
	c.mu.Unlock()
}

func cacheKey(fqdn string, qtype uint16) string {
	return fmt.Sprintf("%d|%s", qtype, fqdn)
}

// minTTL returns the smallest TTL across answer records as a duration, or 0
// when the response carries no answers (e.g. NXDOMAIN).
func minTTL(msg *dns.Msg) time.Duration {
	var smallest uint32

	for _, rr := range msg.Answer {
		ttl := rr.Header().Ttl
		if smallest == 0 || ttl < smallest {
			smallest = ttl
		}
	}

	return time.Duration(smallest) * time.Second
}

func classify(msg *dns.Msg, err error) string {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return OutcomeTimeout
		}

		return OutcomeError
	}

	if msg != nil && msg.Rcode == dns.RcodeNameError {
		return OutcomeNXDomain
	}

	return OutcomeSuccess
}

func isTimeout(err error) bool {
	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}
