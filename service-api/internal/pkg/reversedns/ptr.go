package reversedns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/dnsclient"
)

// LookupPTR resolves all PTR records for each IP. The trimmed hostnames
// (without trailing dot) are returned in resolver-order. IPs with no PTR
// answer map to nil.
//
// When cfg.Resolvers is set, queries go through the shared dnsclient pool
// (retries, round-robin, TCP fallback); otherwise the system resolver is used.
// The observer, if non-nil, receives one callback per query for metrics.
//
// Callers typically treat the first entry as the canonical host hostname
// and persist the remainder as additional Type=PTR records.
func LookupPTR(
	ctx context.Context,
	cfg Config,
	ips []string,
	observer dnsclient.Observer,
) (map[string][]string, error) {
	if len(ips) == 0 {
		return map[string][]string{}, nil
	}

	batchTimeout := cfg.Timeout
	if batchTimeout <= 0 {
		batchTimeout = 2 * time.Minute
	}

	subCtx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()

	nWorkers := cfg.Threads
	if nWorkers < 1 {
		nWorkers = 8
	}

	if nWorkers > len(ips) {
		nWorkers = len(ips)
	}

	perLookupTimeout := cfg.PerLookupTimeout
	if perLookupTimeout <= 0 {
		perLookupTimeout = 5 * time.Second
	}

	lookup, err := newLookupFunc(cfg, perLookupTimeout, observer)
	if err != nil {
		return nil, err
	}

	out := make(map[string][]string, len(ips))

	var mu sync.Mutex

	g, gctx := errgroup.WithContext(subCtx)

	for wid := range nWorkers {
		g.Go(func() error {
			for i := wid; i < len(ips); i += nWorkers {
				ip := ips[i]

				lookupCtx, lookupCancel := context.WithTimeout(gctx, perLookupTimeout)

				names := lookup(lookupCtx, ip)

				lookupCancel()

				mu.Lock()
				out[ip] = names
				mu.Unlock()
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

// lookupFunc resolves a single IP to its cleaned PTR hostnames, or nil on
// failure / no answer.
type lookupFunc func(ctx context.Context, ip string) []string

// newLookupFunc returns a pool-backed resolver when cfg.Resolvers is set,
// otherwise a system-resolver lookup that preserves the legacy behaviour.
func newLookupFunc(cfg Config, perLookupTimeout time.Duration, observer dnsclient.Observer) (lookupFunc, error) {
	if len(cfg.Resolvers) == 0 {
		resolver := net.DefaultResolver

		return func(ctx context.Context, ip string) []string {
			names, err := resolver.LookupAddr(ctx, ip)
			if err != nil {
				return nil
			}

			return clean(names)
		}, nil
	}

	client, err := dnsclient.New(dnsclient.Config{
		Resolvers:       cfg.Resolvers,
		PerQueryTimeout: perLookupTimeout,
		Retries:         cfg.Retries,
		CacheTTL:        cfg.CacheTTL,
		Observer:        observer,
	})
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, ip string) []string {
		arpa, aerr := dns.ReverseAddr(ip)
		if aerr != nil {
			return nil
		}

		resp, qerr := client.Query(ctx, arpa, dns.TypePTR)
		if qerr != nil || resp == nil {
			return nil
		}

		names := make([]string, 0, len(resp.Answer))

		for _, rr := range resp.Answer {
			if ptr, ok := rr.(*dns.PTR); ok {
				names = append(names, ptr.Ptr)
			}
		}

		return clean(names)
	}, nil
}

// clean trims whitespace and trailing dots, dropping empties.
func clean(names []string) []string {
	cleaned := make([]string, 0, len(names))

	for _, n := range names {
		trimmed := strings.TrimSuffix(strings.TrimSpace(n), ".")
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}

	if len(cleaned) == 0 {
		return nil
	}

	return cleaned
}
