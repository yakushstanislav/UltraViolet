// Package portscan provides a TCP connect scanner over an IP iterator and a
// list of ports.
package portscan

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

// Config tunes the scanner.
//
// MaxDialsPerIP caps simultaneous TCP dials toward a single destination IP.
// The default (64) keeps a single-/32 scan parallel enough to stay fast while
// avoiding the SYN-flood pattern that triggers stateful firewall drops and
// produces false-negative "closed" results on rate-limited targets. Set to 0
// to disable the per-IP cap entirely.
type Config struct {
	Workers       int           `env:"PORTSCAN_WORKERS"           env-default:"256"`
	Timeout       time.Duration `env:"PORTSCAN_TIMEOUT"           env-default:"2s"`
	RatePerSec    int           `env:"PORTSCAN_RATE_PER_SEC"      env-default:"1000"`
	MaxDialsPerIP int           `env:"PORTSCAN_MAX_DIALS_PER_IP" env-default:"64"`
}

// OpenPort is one (IP, port) pair that accepted a TCP connection.
type OpenPort struct {
	IP   netip.Addr
	Port uint16
}

// Target groups an IP with the ports to probe on it.
type Target struct {
	IP    netip.Addr
	Ports []uint16
}

// Scanner runs concurrent TCP connect probes.
type Scanner struct {
	config   Config
	ipLimits *ipDialLimiter
}

type ipDialLimiter struct {
	max  int64
	mu   sync.Mutex
	sems map[netip.Addr]*semaphore.Weighted
}

func newIPDialLimiter(maxPerIP int) *ipDialLimiter {
	if maxPerIP <= 0 {
		return nil
	}

	return &ipDialLimiter{
		max:  int64(maxPerIP),
		sems: make(map[netip.Addr]*semaphore.Weighted),
	}
}

func (l *ipDialLimiter) acquire(ctx context.Context, addr netip.Addr) error {
	l.mu.Lock()

	s, ok := l.sems[addr]
	if !ok {
		s = semaphore.NewWeighted(l.max)
		l.sems[addr] = s
	}

	l.mu.Unlock()

	return s.Acquire(ctx, 1)
}

func (l *ipDialLimiter) release(addr netip.Addr) {
	l.mu.Lock()

	s := l.sems[addr]

	l.mu.Unlock()

	if s != nil {
		s.Release(1)
	}
}

// New builds a new scanner.
func New(config Config) *Scanner {
	if config.Workers <= 0 {
		config.Workers = 256
	}

	if config.Timeout <= 0 {
		config.Timeout = 2 * time.Second
	}

	if config.RatePerSec <= 0 {
		config.RatePerSec = 1000
	}

	return &Scanner{
		config:   config,
		ipLimits: newIPDialLimiter(config.MaxDialsPerIP),
	}
}

// Discover walks the CIDR and emits open ports through a Stream. It is the
// Discoverer-shaped entry point for the slow TCP-connect backend. Wait
// is a no-op because all work happens on the scanner's own goroutines and
// completes when the returned channel closes.
func (s *Scanner) Discover(ctx context.Context, cidr string, ports []uint16) (*Stream, error) {
	targets, err := EmitCIDR(ctx, cidr, ports, 0, "", nil)
	if err != nil {
		return nil, err
	}

	return &Stream{
		Ports: s.Scan(ctx, targets),
		Wait:  noopWait,
	}, nil
}

// DiscoverFromTargets feeds an already-computed target channel into the slow
// TCP-connect backend. Used by the random strategy where target generation
// happens outside the normal CIDR walk.
func (s *Scanner) DiscoverFromTargets(ctx context.Context, targets <-chan Target) *Stream {
	return &Stream{
		Ports: s.Scan(ctx, targets),
		Wait:  noopWait,
	}
}

// Scan iterates the targets channel, dialing each (IP, port) with the configured
// concurrency, and forwards open ports to the returned results channel.
//
// The results channel is closed when the targets channel is exhausted and all
// in-flight probes have completed.
func (s *Scanner) Scan(ctx context.Context, targets <-chan Target) <-chan OpenPort {
	results := make(chan OpenPort, s.config.Workers)
	limiter := rate.NewLimiter(rate.Limit(s.config.RatePerSec), s.config.RatePerSec)

	var wg sync.WaitGroup

	jobs := make(chan job, s.config.Workers)

	for range s.config.Workers {
		wg.Add(1)

		go s.worker(ctx, jobs, results, limiter, &wg)
	}

	go func() {
		defer close(jobs)

		for target := range targets {
			for _, port := range target.Ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{ip: target.IP, port: port}:
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

type job struct {
	ip   netip.Addr
	port uint16
}

func (s *Scanner) worker(
	ctx context.Context,
	jobs <-chan job,
	results chan<- OpenPort,
	limiter *rate.Limiter,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	dialer := &net.Dialer{Timeout: s.config.Timeout}

	for j := range jobs {
		s.runDialJob(ctx, results, limiter, dialer, j)
	}
}

func (s *Scanner) runDialJob(
	ctx context.Context,
	results chan<- OpenPort,
	limiter *rate.Limiter,
	dialer *net.Dialer,
	j job,
) {
	if err := limiter.Wait(ctx); err != nil {
		return
	}

	if s.ipLimits != nil {
		if err := s.ipLimits.acquire(ctx, j.ip); err != nil {
			return
		}

		defer s.ipLimits.release(j.ip)
	}

	addr := net.JoinHostPort(j.ip.String(), strconv.Itoa(int(j.port)))

	dialCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)

	conn, err := dialer.DialContext(dialCtx, "tcp", addr)

	cancel()

	if err != nil {
		return
	}

	// SO_LINGER=0 sends RST on Close instead of a full FIN handshake. The
	// open-port signal is already captured by the successful Dial, so the
	// shorter teardown frees local FD/ephemeral-port slots immediately and
	// avoids piling up TIME_WAIT sockets at high RatePerSec.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}

	_ = conn.Close()

	select {
	case <-ctx.Done():
		return
	case results <- OpenPort{IP: j.ip, Port: j.port}:
	}
}
