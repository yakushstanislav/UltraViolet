package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// ProtoFunc gathers protocol-level metadata for a single target using the
// shared Stack helpers. Implementations live one-per-file and register
// themselves through Register() in init().
type ProtoFunc func(ctx context.Context, s *Stack, target Target) (*Result, error)

// protoRegistry maps a TCP port to the prober that owns it. Populated by
// init() blocks in the per-protocol files.
var protoRegistry = map[uint16]ProtoFunc{}

// Register binds fn to one or more TCP ports. Panics on duplicate port —
// init-time misconfiguration is a programmer error, not a runtime one.
func Register(fn ProtoFunc, ports ...uint16) {
	if fn == nil {
		panic("probe.Register: nil ProtoFunc")
	}

	for _, port := range ports {
		if _, dup := protoRegistry[port]; dup {
			panic(fmt.Sprintf("probe.Register: duplicate handler for port %d", port))
		}

		protoRegistry[port] = fn
	}
}

// Stack is the composite Prober. It owns the shared HTTP transport and
// dispatches incoming targets to the per-port handlers, falling back to a
// generic banner read.
type Stack struct {
	cfg           Config
	httpTransport *http.Transport
}

// New builds a Stack with the given config.
func New(cfg Config) *Stack {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	if cfg.BannerTimeout <= 0 {
		cfg.BannerTimeout = 2 * time.Second
	}

	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 256 * 1024
	}

	if cfg.UserAgent == "" {
		cfg.UserAgent = "UltraViolet/1.0"
	}

	// Keep-alives stay on so the per-host request burst (`/`, `/favicon.ico`,
	// `/robots.txt`, `/.well-known/security.txt`, plus optional aux probes)
	// reuses a single TCP+TLS connection. MaxIdleConnsPerHost is bumped above
	// the Go default of 2 to cover that burst without evictions; the short
	// IdleConnTimeout keeps idle pools from accumulating across long scans.
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // scanner probes arbitrary hosts
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
	}

	return &Stack{cfg: cfg, httpTransport: transport}
}

// Probe dispatches to the registered handler for target.Port. When the
// handler only yields a generic tcp result, a second banner/TLS pass runs
// before ingest. Unknown ports go straight to probeBanner.
func (s *Stack) Probe(ctx context.Context, target Target) (*Result, error) {
	if fn, ok := protoRegistry[target.Port]; ok {
		result, err := fn(ctx, s, target)
		if err != nil {
			return nil, err
		}

		if !needsProbeFallback(result) {
			return result, nil
		}

		fallback, fbErr := s.probeBanner(ctx, target)
		if fbErr == nil {
			return mergeProbeResults(result, fallback), nil
		}

		return result, nil
	}

	return s.probeBanner(ctx, target)
}

// dialTCP opens a TCP connection with the stack's full probe timeout.
func (s *Stack) dialTCP(ctx context.Context, target Target) (net.Conn, error) {
	return s.dialTCPWithTimeout(ctx, target, s.probeTimeout(ctx))
}

// dialTCPWithTimeout opens a TCP connection using the supplied timeout for
// both the dial deadline and subsequent IO deadline.
func (s *Stack) dialTCPWithTimeout(ctx context.Context, target Target, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	dialer := &net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(deadlineFromCtx(ctx, timeout))

	return conn, nil
}

// probeTimeout returns the timeout to use for a single probe step, capped by
// the context deadline when one is closer.
func (s *Stack) probeTimeout(ctx context.Context) time.Duration {
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < timeout {
			return rem
		}
	}

	return timeout
}

// bannerTimeout returns the shorter timeout used for the generic banner read,
// capped by the context deadline. Keeps unknown/filtered ports from consuming
// the full probe budget while waiting for a greeting that will never arrive.
func (s *Stack) bannerTimeout(ctx context.Context) time.Duration {
	timeout := s.cfg.BannerTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < timeout {
			return rem
		}
	}

	return timeout
}

// deadlineFromCtx returns the context deadline if present, otherwise now+fallback.
func deadlineFromCtx(ctx context.Context, fallback time.Duration) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}

	return time.Now().Add(fallback)
}

// mustMarshalJSON serialises v for embedding into FingerprintResult.RawJSON.
// Marshalling map[string]any and tagged structs never fails, so an error
// would indicate a programmer mistake — return empty in that case.
func mustMarshalJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}

	return raw
}
