// Package scanner orchestrates CIDR expansion, TCP connect scanning, probing,
// GeoIP enrichment and persistence.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/countryprefix"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/ctlogs"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/dnsclient"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/forwarddns"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/geoip"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/ingest"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/masscan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/nullable"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/portscan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/probe"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/reversedns"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/riskmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmode"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanpolicy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanprofile"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/targetstrategy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/zmap"
	dnsrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/dns"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	hostsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/host"
)

// Config controls scanner execution.
type Config struct {
	PortScan portscan.Config
	// Masscan: scan mode masscan only; see internal/pkg/masscan.Config (MASSCAN_* env).
	Masscan masscan.Config
	// Zmap: scan mode zmap only; see internal/pkg/zmap.Config (ZMAP_* env).
	Zmap             zmap.Config
	Probe            probe.Config
	ReverseDNS       reversedns.Config
	ForwardDNS       forwarddns.Config
	CTLogs           ctlogs.Config
	GeoIP            geoip.Config
	ScanPolicy       scanpolicy.Config
	ProbeWorkers     int           `env:"SCANNER_PROBE_WORKERS"      env-default:"16"`
	ProgressInterval time.Duration `env:"SCANNER_PROGRESS_INTERVAL" env-default:"2s"`
	// UDPProbePorts is a comma-separated list of UDP ports probed for every
	// host discovered during the TCP pass. Use "" to disable. Defaults to the
	// well-known set covered by the built-in UDP probes (DNS, SNMP, NTP,
	// mDNS, IPMI).
	UDPProbePorts []string `env:"SCANNER_UDP_PROBE_PORTS" env-default:"53,161,123,5353,623" env-separator:","`
}

// Request describes one scan execution.
type Request struct {
	// CIDR is the target address space for sequential scans. Empty for random
	// and country.
	CIDR string
	// AllowedCIDRs is the comma-separated allowlist used by the random strategy
	// to sample target IPs. Sourced from SCAN_ALLOWED_CIDRS.
	AllowedCIDRs string
	// Country is the ISO-3166-1 alpha-2 code used by the country strategy.
	// The pipeline resolves it to a list of IPv4 prefixes via its GeoIP-built
	// index. Empty for sequential and random.
	Country        string
	TargetStrategy targetstrategy.Strategy
	// Limit caps the number of hosts iterated. 0 = unlimited.
	Limit uint64
	Ports []uint16
	Mode  scanmode.Mode
	// SlowProfile tunes the built-in TCP-connect scanner (Mode = Slow). Empty
	// means the historical stealth defaults. Ignored by masscan/zmap engines.
	SlowProfile scanprofile.Profile
	Progress    func(context.Context, Stats) error
	// ResumeCursor lets a paused scan resume from where it left off. For the
	// sequential/slow strategy it is the last emitted IP; for random/slow it
	// is the cumulative emitted-IP count as a decimal string. Empty means
	// "start from the beginning". Ignored by masscan/zmap engines.
	ResumeCursor string
	// CursorUpdate, when non-nil, is invoked by the target emitter before each
	// IP is offered to the scanner pool, so the caller can persist resume
	// state. It must be cheap; throttle disk writes externally.
	CursorUpdate portscan.CursorUpdate
	// InitialStats seeds the atomic counters so resumed scans keep climbing
	// instead of restarting from zero in the UI.
	InitialStats Stats
}

// Stats are counters emitted during a scan.
type Stats struct {
	OpenPorts uint64 `json:"open_ports"`
	Probed    uint64 `json:"probed"`
	Stored    uint64 `json:"stored"`
	Errors    uint64 `json:"errors"`
	// EmittedTargets is the number of target IPs the slow engine has handed
	// to the worker pool so far. It is the source of truth for the user-facing
	// progress bar (numerator: emitted; denominator: CIDR host count or
	// HostLimit). The masscan/zmap engines do not populate this field.
	EmittedTargets uint64 `json:"emitted_targets"`
}

// Map returns Stats as a JSON-friendly map.
func (s Stats) Map() map[string]any {
	return map[string]any{
		"open_ports":      s.OpenPorts,
		"probed":          s.Probed,
		"stored":          s.Stored,
		"errors":          s.Errors,
		"emitted_targets": s.EmittedTargets,
	}
}

// serviceIDCollector accumulates service IDs whose fingerprints changed during
// a scan so CVE matching can be batched after all workers finish.
type serviceIDCollector struct {
	mu  sync.Mutex
	ids []uint64
}

func (c *serviceIDCollector) add(id uint64) {
	c.mu.Lock()
	c.ids = append(c.ids, id)
	c.mu.Unlock()
}

func (c *serviceIDCollector) snapshot() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]uint64, len(c.ids))
	copy(out, c.ids)

	return out
}

// hostIDCollector accumulates host IDs touched during a scan batch.
type hostIDCollector struct {
	mu  sync.Mutex
	ids map[uint64]struct{}
}

func (c *hostIDCollector) add(id uint64) {
	if id == 0 {
		return
	}

	c.mu.Lock()
	if c.ids == nil {
		c.ids = make(map[uint64]struct{})
	}

	c.ids[id] = struct{}{}
	c.mu.Unlock()
}

func (c *hostIDCollector) snapshot() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]uint64, 0, len(c.ids))
	for id := range c.ids {
		out = append(out, id)
	}

	return out
}

// HostRiskAggregator recomputes persisted host scores after ingest batches.
type HostRiskAggregator interface {
	AggregateForHost(ctx context.Context, hostID uint64) error
}

// Pipeline executes scans and persists results.
type Pipeline struct {
	config         Config
	scanner        *portscan.Scanner
	prober         probe.Prober
	geoDB          *geoip.DB
	countryIndex   *countryprefix.Index
	ingestor       *ingest.Ingestor
	cveMatcher     ingest.CVEMatcher
	hostRisk       HostRiskAggregator
	hostRepository host.Repository
	dnsRepository  dnsrepository.Repository
	ctlogsClient   *ctlogs.Client
	logger         *zap.SugaredLogger
}

// NewPipeline builds a Pipeline and opens optional GeoIP databases.
func NewPipeline(config Config, ingestor *ingest.Ingestor, hostRepository host.Repository, dnsRepository dnsrepository.Repository, logger *zap.SugaredLogger) (*Pipeline, error) {
	if config.ProgressInterval <= 0 {
		config.ProgressInterval = 2 * time.Second
	}

	if config.ProbeWorkers <= 0 {
		config.ProbeWorkers = 16
	}

	geoDB, err := geoip.Open(&config.GeoIP)
	if err != nil {
		return nil, err
	}

	countryIndex, err := geoDB.BuildCountryPrefixIndex()
	if err != nil {
		geoDB.Close()

		return nil, fmt.Errorf("can't build GeoIP country prefix index: %w", err)
	}

	if countryIndex != nil {
		logger.Infow("Built country prefix index",
			zap.Int("countries", countryIndex.Len()),
			zap.Int("ipv4_prefixes", countryIndex.PrefixCount()),
		)
	}

	prober := probe.New(config.Probe)

	var ctlogsClient *ctlogs.Client
	if config.CTLogs.Enabled {
		ctlogsClient = ctlogs.New(config.CTLogs)
	}

	return &Pipeline{
		config:         config,
		scanner:        portscan.New(config.PortScan),
		prober:         prober,
		geoDB:          geoDB,
		countryIndex:   countryIndex,
		ingestor:       ingestor,
		hostRepository: hostRepository,
		dnsRepository:  dnsRepository,
		ctlogsClient:   ctlogsClient,
		logger:         logger,
	}, nil
}

// Close releases resources held by Pipeline.
func (p *Pipeline) Close() {
	if p == nil {
		return
	}

	p.geoDB.Close()
}

// WithCVEMatcher wires a CVE matcher invoked in batch after each scan
// completes. Pass nil to disable CVE matching (default).
func (p *Pipeline) WithCVEMatcher(matcher ingest.CVEMatcher) *Pipeline {
	p.cveMatcher = matcher

	return p
}

// WithHostRiskAggregator wires host score recomputation after each scan batch.
func (p *Pipeline) WithHostRiskAggregator(aggregator HostRiskAggregator) *Pipeline {
	p.hostRisk = aggregator

	return p
}

// AllowedCIDRs returns the comma-separated allowed CIDR list from the pipeline's
// scan policy. Workers pass this value into Request.AllowedCIDRs for random scans.
func (p *Pipeline) AllowedCIDRs() string {
	return p.config.ScanPolicy.AllowedCIDRs
}

// CountryPrefixIndex returns the GeoIP-derived country → IPv4 prefixes index.
// nil means no country MMDB is loaded — callers (e.g. the scan service)
// treat that as "country strategy unavailable".
func (p *Pipeline) CountryPrefixIndex() *countryprefix.Index {
	return p.countryIndex
}

// ptrCache accumulates unique IP strings for a bulk reverse-DNS lookup after
// all workers finish. The mutex makes it safe for concurrent workers.
type ptrCache struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newPtrCache() *ptrCache {
	return &ptrCache{seen: make(map[string]struct{})}
}

func (c *ptrCache) add(ip string) {
	c.mu.Lock()
	c.seen[ip] = struct{}{}
	c.mu.Unlock()
}

func (c *ptrCache) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]string, 0, len(c.seen))
	for ip := range c.seen {
		out = append(out, ip)
	}

	return out
}

// fatalErr stores the first fatal error from the worker pool. Only the first
// error is kept because it triggers cancellation; later errors are noise.
type fatalErr struct {
	mu  sync.Mutex
	err error
}

func (f *fatalErr) set(err error) {
	f.mu.Lock()
	if f.err == nil {
		f.err = err
	}
	f.mu.Unlock()
}

func (f *fatalErr) get() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.err
}

// pipelineStats holds the atomic counters and progress throttle shared across
// the worker pool and the main loop.
type pipelineStats struct {
	openPorts      atomic.Uint64
	probed         atomic.Uint64
	stored         atomic.Uint64
	errors         atomic.Uint64
	emittedTargets atomic.Uint64
	lastNano       atomic.Int64
}

func (s *pipelineStats) snapshot() Stats {
	return Stats{
		OpenPorts:      s.openPorts.Load(),
		Probed:         s.probed.Load(),
		Stored:         s.stored.Load(),
		Errors:         s.errors.Load(),
		EmittedTargets: s.emittedTargets.Load(),
	}
}

// Run executes a scan request until the CIDR is exhausted or ctx is done.
func (p *Pipeline) Run(ctx context.Context, request Request) (Stats, error) {
	strategy := request.TargetStrategy
	if strategy == "" {
		strategy = targetstrategy.Sequential
	}

	if strategy == targetstrategy.Sequential {
		if err := p.config.ScanPolicy.Validate(request.CIDR, request.Ports); err != nil {
			return Stats{}, fmt.Errorf("scan request rejected by policy: %w", err)
		}
	} else {
		if err := p.config.ScanPolicy.ValidatePorts(request.Ports); err != nil {
			return Stats{}, fmt.Errorf("scan request rejected by policy: %w", err)
		}
	}

	if strategy == targetstrategy.Country {
		if p.countryIndex == nil || p.countryIndex.Len() == 0 {
			return Stats{}, errors.New("country strategy requires GeoIP country database")
		}

		if len(p.countryIndex.Prefixes(request.Country)) == 0 {
			return Stats{}, fmt.Errorf("country %q has no IPv4 prefixes in GeoIP database", request.Country)
		}
	}

	mode := request.Mode
	if mode == "" {
		mode = scanmode.Slow
	}

	var (
		wg        sync.WaitGroup
		stats     pipelineStats
		fatal     fatalErr
		ptr       *ptrCache
		dirty     serviceIDCollector
		hostDirty hostIDCollector
	)

	stats.openPorts.Store(request.InitialStats.OpenPorts)
	stats.probed.Store(request.InitialStats.Probed)
	stats.stored.Store(request.InitialStats.Stored)
	stats.errors.Store(request.InitialStats.Errors)
	stats.emittedTargets.Store(request.InitialStats.EmittedTargets)

	// Wrap the caller's cursor callback so each emitted target bumps the
	// counter that drives the progress bar. The slow engine is the only one
	// that invokes CursorUpdate, so masscan/zmap leave emittedTargets at 0
	// and the frontend hides the bar for them.
	cursorUpdate := request.CursorUpdate
	wrappedCursorUpdate := func(ctx context.Context, ip string) error {
		stats.emittedTargets.Add(1)
		p.reportProgress(ctx, request, &stats)

		if cursorUpdate == nil {
			return nil
		}

		return cursorUpdate(ctx, ip)
	}

	stream, err := p.startOpenPortStream(
		ctx,
		mode,
		request.SlowProfile,
		strategy,
		request.CIDR,
		request.AllowedCIDRs,
		request.Country,
		request.Ports,
		request.Limit,
		request.ResumeCursor,
		wrappedCursorUpdate,
	)
	if err != nil {
		return Stats{}, err
	}

	workers := p.config.ProbeWorkers
	if workers <= 0 {
		workers = 16
	}

	taskCh := make(chan portscan.OpenPort, workers*2)

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if (p.config.ReverseDNS.Enabled || p.config.ForwardDNS.Enabled) && p.hostRepository != nil {
		ptr = newPtrCache()
	}

	hostsForUDP := newPtrCache()

	for range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			p.runWorker(subCtx, taskCh, &stats, ptr, &fatal, cancel, &dirty, &hostDirty)
		}()
	}

	drainOpenPorts := false

	for openPort := range stream.ch {
		stats.openPorts.Add(1)

		if ptr != nil {
			ptr.add(openPort.IP.String())
		}

		hostsForUDP.add(openPort.IP.String())

		p.reportProgress(ctx, request, &stats)

		if drainOpenPorts {
			continue
		}

		select {
		case <-subCtx.Done():
			drainOpenPorts = true
		case taskCh <- openPort:
		}
	}

	close(taskCh)

	wg.Wait()

	if ptr != nil {
		scannedIPs := ptr.snapshot()

		var ptrMap map[string][]string
		if p.config.ReverseDNS.Enabled {
			ptrMap = p.updatePTRHostnames(ctx, scannedIPs)
		}

		p.enrichDNSRecords(ctx, ptrMap, scannedIPs)
	}

	p.probeUDPForHosts(ctx, hostsForUDP, &stats, &dirty, &hostDirty)

	p.flushCVEMatches(ctx, &dirty)
	p.flushHostRisk(ctx, &hostDirty)

	waitErr := stream.wait()

	out := stats.snapshot()

	if err := fatal.get(); err != nil {
		return out, err
	}

	if waitErr != nil {
		return out, waitErr
	}

	if err := ctx.Err(); err != nil {
		return out, err
	}

	if request.Progress != nil {
		if err := request.Progress(ctx, out); err != nil {
			return out, fmt.Errorf("can't report final progress: %w", err)
		}
	}

	return out, nil
}

// probeUDPForHosts runs every configured UDP probe against every host that
// had at least one open TCP port. Results are persisted with UDP transport.
func (p *Pipeline) probeUDPForHosts(ctx context.Context, hosts *ptrCache, stats *pipelineStats, dirty *serviceIDCollector, hostDirty *hostIDCollector) {
	if len(p.config.UDPProbePorts) == 0 || hosts == nil {
		return
	}

	stack, ok := p.prober.(*probe.Stack)
	if !ok {
		return
	}

	ports := make([]uint16, 0, len(p.config.UDPProbePorts))

	for _, raw := range p.config.UDPProbePorts {
		port, err := strconv.ParseUint(raw, 10, 16)
		if err != nil {
			continue
		}

		ports = append(ports, uint16(port))
	}

	if len(ports) == 0 {
		return
	}

	for _, ipStr := range hosts.snapshot() {
		if ctx.Err() != nil {
			return
		}

		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}

		for _, port := range ports {
			if ctx.Err() != nil {
				return
			}

			result, err := stack.ProbeUDP(ctx, probe.Target{IP: ip, Port: port, Transport: probe.TransportUDP})
			if err != nil || result == nil {
				continue
			}

			stats.probed.Add(1)

			geoResult, geoErr := p.geoDB.Lookup(ip)
			if geoErr != nil {
				stats.errors.Add(1)

				p.logger.Warnw("Can't lookup GeoIP for UDP host",
					zap.String("ip", ip.String()),
					zap.Error(geoErr),
				)
			}

			serviceID, hostID, changed, err := p.ingestor.Ingest(ctx, result, geoResult)
			if err != nil {
				stats.errors.Add(1)

				p.logger.Warnw("Can't persist UDP probe result",
					zap.String("ip", ip.String()),
					zap.Uint16("port", port),
					zap.Error(err),
				)

				continue
			}

			hostDirty.add(hostID)

			if changed {
				dirty.add(serviceID)
			}

			stats.stored.Add(1)
		}
	}
}

// flushCVEMatches runs CVE matching for every service whose fingerprint
// changed during the scan. Calls are dispatched with bounded parallelism so
// the database isn't flooded, and individual failures are swallowed — the
// background cvematch worker will catch any misses on its next run.
func (p *Pipeline) flushCVEMatches(ctx context.Context, dirty *serviceIDCollector) {
	if p.cveMatcher == nil {
		return
	}

	ids := dirty.snapshot()
	if len(ids) == 0 {
		return
	}

	const batchWorkers = 8

	sem := make(chan struct{}, batchWorkers)

	var flushWg sync.WaitGroup

	for _, id := range ids {
		sem <- struct{}{}

		flushWg.Add(1)

		go func(svcID uint64) {
			defer func() {
				<-sem
				flushWg.Done()
			}()

			_, _ = p.cveMatcher.MatchService(ctx, svcID)
		}(id)
	}

	flushWg.Wait()
}

func (p *Pipeline) flushHostRisk(ctx context.Context, hostDirty *hostIDCollector) {
	if p.hostRisk == nil || hostDirty == nil {
		return
	}

	ingestCtx := hostsvc.WithTrigger(ctx, riskmetrics.TriggerIngest)

	for _, hostID := range hostDirty.snapshot() {
		if err := p.hostRisk.AggregateForHost(ingestCtx, hostID); err != nil {
			p.logger.Warnw("Host risk aggregate failed after ingest",
				zap.Uint64("host_id", hostID),
				zap.Error(err),
			)
		}
	}
}

// runWorker probes each open port, enriches with GeoIP and persists the result.
// On a fatal ingest error it records the error and cancels the shared context.
func (p *Pipeline) runWorker(
	ctx context.Context,
	taskCh <-chan portscan.OpenPort,
	stats *pipelineStats,
	ptr *ptrCache,
	fatal *fatalErr,
	cancel context.CancelFunc,
	dirty *serviceIDCollector,
	hostDirty *hostIDCollector,
) {
	for openPort := range taskCh {
		if ctx.Err() != nil {
			return
		}

		result, err := p.prober.Probe(ctx, probe.Target{
			IP:   openPort.IP,
			Port: openPort.Port,
		})
		if err != nil {
			stats.errors.Add(1)

			p.logger.Debugw("Can't probe open port",
				zap.String("ip", openPort.IP.String()),
				zap.Uint16("port", openPort.Port),
				zap.Error(err),
			)

			continue
		}

		stats.probed.Add(1)

		geoResult, geoErr := p.geoDB.Lookup(openPort.IP)
		if geoErr != nil {
			stats.errors.Add(1)

			p.logger.Warnw("Can't lookup GeoIP",
				zap.String("ip", openPort.IP.String()),
				zap.Error(geoErr),
			)
		}

		serviceID, hostID, changed, err := p.ingestor.Ingest(ctx, result, geoResult)
		if err != nil {
			stats.errors.Add(1)
			fatal.set(fmt.Errorf("can't persist probe result: %w", err))
			cancel()

			return
		}

		hostDirty.add(hostID)

		if changed {
			dirty.add(serviceID)
		}

		stats.stored.Add(1)
	}
}

// updatePTRHostnames resolves PTR records for collected IPs, writes the
// first hostname back to uv_host.ptr_hostname and returns the full
// ip → []hostname map for downstream forward DNS enrichment. Additional
// PTR names (beyond the first) are persisted as Type=PTR DNS records by
// enrichDNSRecords.
func (p *Pipeline) updatePTRHostnames(ctx context.Context, ips []string) map[string][]string {
	if len(ips) == 0 || ctx.Err() != nil {
		return nil
	}

	ptrMap, err := reversedns.LookupPTR(ctx, p.config.ReverseDNS, ips, dnsObserver("reverse"))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}

		scanmetrics.ScanErrorsTotal.WithLabelValues("dns").Inc()

		p.logger.Warnw("Can't run reverse DNS PTR batch", zap.Error(err))

		return nil
	}

	for ipStr, hostnames := range ptrMap {
		if ctx.Err() != nil {
			return ptrMap
		}

		addr, paErr := netip.ParseAddr(ipStr)
		if paErr != nil {
			continue
		}

		var primary string
		if len(hostnames) > 0 {
			primary = hostnames[0]
		}

		ptr := nullable.StringPtr(primary)

		if uerr := p.hostRepository.UpdatePTRHostname(ctx, addr, ptr); uerr != nil {
			if errors.Is(uerr, context.Canceled) {
				return ptrMap
			}

			p.logger.Debugw("Can't update PTR hostname",
				zap.String("ip", ipStr),
				zap.Error(uerr),
			)
		}
	}

	return ptrMap
}

// nameInfo records where a hostname came from. origins is the set of scanned
// IPs that surfaced the name (empty for CT-only discoveries); source carries
// the strongest provenance seen, ranked ptr > san > ct.
type nameInfo struct {
	origins map[string]struct{}
	source  string
}

// sourceRank orders provenance so the most trustworthy source wins when a
// hostname is seen from several places.
func sourceRank(source string) int {
	switch source {
	case "ptr":
		return 3
	case "san":
		return 2
	case "ct":
		return 1
	default:
		return 0
	}
}

// enrichDNSRecords gathers hostnames from three sources — PTR, TLS SANs, and
// (optionally) CT logs — resolves forward DNS for the deduplicated set, and
// upserts every result against the host_id of the IP that originated the
// hostname. Each record carries its provenance (source) and a forward_confirmed
// flag set when the hostname forward-resolves back to the scanned IP (FCrDNS).
// Additional PTR names (beyond the primary) are stored as Type=PTR records too.
func (p *Pipeline) enrichDNSRecords(ctx context.Context, ptrMap map[string][]string, scannedIPs []string) {
	if !p.config.ForwardDNS.Enabled || p.dnsRepository == nil || len(scannedIPs) == 0 {
		return
	}

	if ctx.Err() != nil {
		return
	}

	hostIDs, err := p.hostRepository.GetIDsByIPs(ctx, scannedIPs)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}

		scanmetrics.ScanErrorsTotal.WithLabelValues("dns").Inc()

		p.logger.Warnw("Can't batch-fetch host IDs for DNS enrichment", zap.Error(err))

		return
	}

	if len(hostIDs) == 0 {
		return
	}

	names := p.collectHostnames(ctx, ptrMap, scannedIPs)
	if len(names) == 0 {
		return
	}

	hostnames := make([]string, 0, len(names))

	for name := range names {
		hostnames = append(hostnames, name)
	}

	recordsByHostname, err := forwarddns.LookupAll(ctx, p.config.ForwardDNS, hostnames, dnsObserver("forward"))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}

		scanmetrics.ScanErrorsTotal.WithLabelValues("dns").Inc()

		p.logger.Warnw("Can't run forward DNS batch", zap.Error(err))
	}

	forwardIPs := forwardAddresses(recordsByHostname)
	persist := make(map[uint64][]dnsrepository.Record)

	// Additional PTR names (beyond the primary) become Type=PTR records,
	// forward-confirmed when the name resolves back to the originating IP.
	for ipStr, ptrNames := range ptrMap {
		hostID, ok := hostIDs[ipStr]
		if !ok || len(ptrNames) <= 1 {
			continue
		}

		for _, extra := range ptrNames[1:] {
			// forwardIPs is keyed by the normalized (lower-cased) hostname used
			// for the forward batch, so match the PTR name the same way.
			_, confirmed := forwardIPs[strings.ToLower(extra)][ipStr]

			persist[hostID] = append(persist[hostID], dnsrepository.Record{
				RecordType:       "PTR",
				Name:             ipStr,
				Value:            extra,
				Source:           "ptr",
				ForwardConfirmed: confirmed,
			})
		}
	}

	for hostname, recs := range recordsByHostname {
		if len(recs) == 0 {
			continue
		}

		anchors := p.resolveAnchors(hostname, names, recs, hostIDs, forwardIPs[hostname])
		if len(anchors) == 0 {
			continue
		}

		source := "ct"
		if info := names[hostname]; info != nil && info.source != "" {
			source = info.source
		}

		for hostID, confirmed := range anchors {
			for _, r := range recs {
				persist[hostID] = append(persist[hostID], dnsrepository.Record{
					RecordType:       r.Type,
					Name:             r.Name,
					Value:            r.Value,
					Source:           source,
					ForwardConfirmed: confirmed,
				})
			}
		}
	}

	p.persistDNSRecords(ctx, persist, len(hostnames))
}

// persistDNSRecords upserts the per-host record batches and records coverage
// metrics. A canceled context aborts the remaining writes.
func (p *Pipeline) persistDNSRecords(ctx context.Context, persist map[uint64][]dnsrepository.Record, hostnameCount int) {
	hostsWithRecords := 0

	for hostID, records := range persist {
		if ctx.Err() != nil {
			return
		}

		if uerr := p.dnsRepository.UpsertRecords(ctx, hostID, records); uerr != nil {
			if errors.Is(uerr, context.Canceled) {
				return
			}

			scanmetrics.ScanErrorsTotal.WithLabelValues("dns").Inc()

			p.logger.Debugw("Can't upsert DNS records",
				zap.Uint64("host_id", hostID),
				zap.Error(uerr),
			)

			continue
		}

		hostsWithRecords++

		for _, r := range records {
			scanmetrics.DNSRecordsPersistedTotal.WithLabelValues(r.RecordType).Inc()
		}
	}

	if hostsWithRecords > 0 {
		scanmetrics.DNSHostsWithRecordsTotal.Add(float64(hostsWithRecords))
	}

	p.logger.Infow("DNS enrichment complete",
		zap.Int("hostnames", hostnameCount),
		zap.Int("hosts_with_records", hostsWithRecords),
	)
}

// forwardAddresses indexes the A/AAAA values resolved for each hostname, used
// to confirm reverse DNS (FCrDNS) and to anchor CT-only names.
func forwardAddresses(recordsByHostname map[string][]forwarddns.Record) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(recordsByHostname))

	for hostname, recs := range recordsByHostname {
		for _, r := range recs {
			if r.Type != "A" && r.Type != "AAAA" {
				continue
			}

			bucket, ok := out[hostname]
			if !ok {
				bucket = map[string]struct{}{}
				out[hostname] = bucket
			}

			bucket[r.Value] = struct{}{}
		}
	}

	return out
}

// dnsObserver returns a dnsclient.Observer that feeds per-query metrics tagged
// with the given direction (forward | reverse).
func dnsObserver(direction string) dnsclient.Observer {
	return func(qtype uint16, outcome string, dur time.Duration) {
		scanmetrics.DNSLookupsTotal.WithLabelValues(direction, dns.TypeToString[qtype], outcome).Inc()
		scanmetrics.DNSLookupDurationSeconds.WithLabelValues(direction).Observe(dur.Seconds())
	}
}

// collectHostnames builds hostname → nameInfo from PTR, SAN and CT log sources.
// An origin IP set may be empty for CT-discovered names — resolveAnchors
// handles those by walking the resolved A/AAAA values back to scanned IPs.
func (p *Pipeline) collectHostnames(
	ctx context.Context,
	ptrMap map[string][]string,
	scannedIPs []string,
) map[string]*nameInfo {
	names := make(map[string]*nameInfo)

	addOrigin := func(name, originIP, source string) {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" || strings.HasPrefix(name, "*.") {
			return
		}

		info, ok := names[name]
		if !ok {
			info = &nameInfo{origins: map[string]struct{}{}}
			names[name] = info
		}

		if originIP != "" {
			info.origins[originIP] = struct{}{}
		}

		if sourceRank(source) > sourceRank(info.source) {
			info.source = source
		}
	}

	for ipStr, hostnames := range ptrMap {
		for _, n := range hostnames {
			addOrigin(n, ipStr, "ptr")
		}
	}

	sanMap, err := p.hostRepository.ListSANsByIPs(ctx, scannedIPs)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			p.logger.Debugw("Can't fetch SANs for DNS enrichment", zap.Error(err))
		}
	} else {
		for ipStr, sans := range sanMap {
			for _, s := range sans {
				addOrigin(s, ipStr, "san")
			}
		}
	}

	if p.ctlogsClient != nil {
		apexes := apexDomains(names)

		for apex := range apexes {
			if ctx.Err() != nil {
				break
			}

			entries, cterr := p.ctlogsClient.LookupByDomain(ctx, apex)
			if cterr != nil {
				p.logger.Debugw("Can't query CT logs",
					zap.String("apex", apex),
					zap.Error(cterr),
				)

				continue
			}

			for _, e := range entries {
				for _, n := range strings.Split(e.NameValue, "\n") {
					addOrigin(n, "", "ct")
				}

				addOrigin(e.CommonName, "", "ct")
			}
		}
	}

	return names
}

// resolveAnchors returns the host_ids a hostname's records should be persisted
// under, mapped to whether the binding is forward-confirmed. PTR/SAN-derived
// names use their origin IPs directly and are confirmed when the hostname
// forward-resolves back to that IP. CT-only names (empty origin set) anchor to
// any A/AAAA value that resolves into a scanned IP — confirmed by construction,
// since the record value is the scanned IP itself.
func (p *Pipeline) resolveAnchors(
	hostname string,
	names map[string]*nameInfo,
	recs []forwarddns.Record,
	hostIDs map[string]uint64,
	forwardIPs map[string]struct{},
) map[uint64]bool {
	out := make(map[uint64]bool)

	if info, ok := names[hostname]; ok && len(info.origins) > 0 {
		for ipStr := range info.origins {
			id, ok := hostIDs[ipStr]
			if !ok {
				continue
			}

			_, confirmed := forwardIPs[ipStr]
			out[id] = out[id] || confirmed
		}

		return out
	}

	for _, r := range recs {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}

		if id, ok := hostIDs[r.Value]; ok {
			out[id] = true
		}
	}

	return out
}

// apexDomains extracts the rightmost label.tld pair from each known
// hostname, used to seed CT log queries. Wildcards and bare TLDs are
// skipped. The eTLD is a rough heuristic — pulling psl is overkill for
// scanner-side enrichment.
func apexDomains(names map[string]*nameInfo) map[string]struct{} {
	out := make(map[string]struct{})

	for name := range names {
		labels := strings.Split(name, ".")
		if len(labels) < 2 {
			continue
		}

		apex := labels[len(labels)-2] + "." + labels[len(labels)-1]
		out[apex] = struct{}{}
	}

	return out
}

func (p *Pipeline) reportProgress(
	ctx context.Context,
	request Request,
	stats *pipelineStats,
) {
	if request.Progress == nil {
		return
	}

	now := time.Now().UnixNano()

	last := stats.lastNano.Load()
	if last == 0 {
		if !stats.lastNano.CompareAndSwap(0, now) {
			return
		}

		return
	}

	if time.Duration(now-last) < p.config.ProgressInterval {
		return
	}

	if !stats.lastNano.CompareAndSwap(last, now) {
		return
	}

	if err := request.Progress(ctx, stats.snapshot()); err != nil {
		p.logger.Warnw("Can't report scan progress", zap.Error(err))
	}
}
