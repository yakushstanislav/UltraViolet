package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	productMemcached    = "memcached"
	memcachedReadBudget = 8 * 1024
)

func init() {
	Register(probeMemcached, 11211)
}

// memcachedFacts collects what we learned from probing a memcached server.
type memcachedFacts struct {
	Version      string            `json:"version,omitempty"`
	VersionRaw   string            `json:"version_raw,omitempty"`
	StatsExcerpt map[string]string `json:"stats,omitempty"`
	SASLDetected bool              `json:"sasl_detected,omitempty"`
}

// probeMemcached sends `version` (and `stats` when allowed) over the ASCII
// protocol and packages the result into a fingerprint.
func probeMemcached(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial Memcached: %w", err)
	}

	defer func() { _ = conn.Close() }()

	facts, err := readMemcachedFacts(ctx, conn, s.probeTimeout(ctx))
	if err != nil {
		return nil, err
	}

	authRequired := facts.SASLDetected

	fp := &FingerprintResult{
		Product:      productMemcached,
		Version:      facts.Version,
		AuthRequired: &authRequired,
		Anonymous:    !authRequired,
		RawJSON:      mustMarshalJSON(facts),
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Fingerprint: fp,
	}, nil
}

// readMemcachedFacts runs the actual protocol exchange.
func readMemcachedFacts(ctx context.Context, conn net.Conn, to time.Duration) (*memcachedFacts, error) {
	deadline := time.Now().Add(to)

	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return nil, fmt.Errorf("can't write Memcached version command: %w", err)
	}

	reader := bufio.NewReaderSize(conn, memcachedReadBudget)

	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("can't read Memcached version response: %w", err)
	}

	facts := &memcachedFacts{VersionRaw: strings.TrimRight(line, "\r\n")}

	switch {
	case strings.HasPrefix(facts.VersionRaw, "VERSION "):
		facts.Version = strings.TrimPrefix(facts.VersionRaw, "VERSION ")
	case strings.HasPrefix(facts.VersionRaw, "ERROR"), strings.HasPrefix(facts.VersionRaw, "CLIENT_ERROR"):
		facts.SASLDetected = true

		return facts, nil
	default:
		return nil, fmt.Errorf("unexpected Memcached response %q", facts.VersionRaw)
	}

	if stats, _ := readMemcachedStats(conn, reader, deadline); stats != nil {
		facts.StatsExcerpt = stats
	}

	return facts, nil
}

// readMemcachedStats sends `stats\r\n` and reads until END, picking out a
// small set of useful keys to keep the raw blob compact.
func readMemcachedStats(conn net.Conn, reader *bufio.Reader, deadline time.Time) (map[string]string, error) {
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte("stats\r\n")); err != nil {
		return nil, err
	}

	wanted := map[string]struct{}{
		"pid":               {},
		"uptime":            {},
		"version":           {},
		"libevent":          {},
		"pointer_size":      {},
		"curr_connections":  {},
		"total_connections": {},
		"limit_maxbytes":    {},
	}

	out := make(map[string]string, len(wanted))
	totalRead := 0

	for {
		if totalRead > memcachedReadBudget {
			return out, nil
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return out, err
		}

		totalRead += len(line)

		line = strings.TrimRight(line, "\r\n")
		if line == "END" {
			return out, nil
		}

		if !strings.HasPrefix(line, "STAT ") {
			continue
		}

		parts := strings.SplitN(strings.TrimPrefix(line, "STAT "), " ", 2)
		if len(parts) != 2 {
			continue
		}

		if _, ok := wanted[parts[0]]; ok {
			out[parts[0]] = parts[1]
		}
	}
}
