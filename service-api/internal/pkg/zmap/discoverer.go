package zmap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/portscan"
)

// New builds a Discoverer that executes the zmap CLI. The returned type
// satisfies portscan.Discoverer (CIDR mode) and additionally exposes
// DiscoverIPs for the random strategy (pre-materialised IP list).
func New(cfg Config) *Discoverer {
	return &Discoverer{cfg: cfg}
}

// Discoverer wraps the zmap CLI invocation.
type Discoverer struct {
	cfg Config
}

// Discover validates the input and launches zmap via the shared
// Subprocess scaffolding, parsing its CSV stdout (saddr,sport).
func (d *Discoverer) Discover(ctx context.Context, cidr string, ports []uint16) (*portscan.Stream, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("can't parse CIDR for zmap: %w", err)
	}

	if !prefix.Addr().Is4() {
		return nil, errors.New("zmap mode supports IPv4 targets only")
	}

	portSpec := portscan.FormatPortSpec(ports)
	if portSpec == "" {
		return nil, errors.New("zmap requires at least one port")
	}

	return portscan.Subprocess{
		Name:      "zmap",
		Binary:    binaryOrDefault(d.cfg.Binary),
		Args:      buildArgs(d.cfg, cidr, portSpec),
		ParseLine: parseLine,
	}.Run(ctx)
}

// DiscoverIPs runs zmap against a pre-materialised list of IPv4 targets.
// The IPs are written to an OS temp file passed via --allowlist-file;
// combined with the positional 0.0.0.0/0 target zmap scans exactly the
// listed addresses. The file is unlinked right after the subprocess
// starts — zmap holds the open fd until exit.
func (d *Discoverer) DiscoverIPs(ctx context.Context, ips []netip.Addr, ports []uint16) (*portscan.Stream, error) {
	if len(ips) == 0 {
		return nil, errors.New("zmap requires at least one IP target")
	}

	portSpec := portscan.FormatPortSpec(ports)
	if portSpec == "" {
		return nil, errors.New("zmap requires at least one port")
	}

	for _, ip := range ips {
		if !ip.Is4() {
			return nil, errors.New("zmap mode supports IPv4 targets only")
		}
	}

	path, err := portscan.WriteIPListFile("uv-zmap-targets-*.txt", ips)
	if err != nil {
		return nil, err
	}

	stream, err := portscan.Subprocess{
		Name:      "zmap",
		Binary:    binaryOrDefault(d.cfg.Binary),
		Args:      buildArgsIPList(d.cfg, path, portSpec),
		ParseLine: parseLine,
	}.Run(ctx)
	if err != nil {
		_ = os.Remove(path)

		return nil, err
	}

	_ = os.Remove(path)

	return stream, nil
}

func binaryOrDefault(bin string) string {
	if bin == "" {
		return "zmap"
	}

	return bin
}

func buildArgs(cfg Config, cidr, portSpec string) []string {
	rate := cfg.RatePerSec
	if rate <= 0 {
		rate = 1000
	}

	cooldown := cfg.CooldownSeconds
	if cooldown <= 0 {
		cooldown = 8
	}

	args := make([]string, 0, 20)

	if iface := strings.TrimSpace(cfg.Interface); iface != "" {
		args = append(args, "-i", iface)
	}

	args = append(args,
		"-q",
		"-r", strconv.Itoa(rate),
		"-c", strconv.Itoa(cooldown),
		"-p", portSpec,
		"-f", "saddr,sport",
		"-O", "csv",
		"--no-header-row",
		"-o", "-",
		cidr,
	)

	return args
}

// buildArgsIPList builds the zmap argv for the random strategy: targets
// come from an --allowlist-file plus a 0.0.0.0/0 positional so zmap
// intersects to exactly the listed addresses. All other flags (rate,
// cooldown, port spec, output format, optional interface) mirror
// buildArgs.
func buildArgsIPList(cfg Config, listPath, portSpec string) []string {
	rate := cfg.RatePerSec
	if rate <= 0 {
		rate = 1000
	}

	cooldown := cfg.CooldownSeconds
	if cooldown <= 0 {
		cooldown = 8
	}

	args := make([]string, 0, 20)

	if iface := strings.TrimSpace(cfg.Interface); iface != "" {
		args = append(args, "-i", iface)
	}

	args = append(args,
		"-q",
		"-r", strconv.Itoa(rate),
		"-c", strconv.Itoa(cooldown),
		"-p", portSpec,
		"-f", "saddr,sport",
		"-O", "csv",
		"--no-header-row",
		"-o", "-",
		"--allowlist-file="+listPath,
		"0.0.0.0/0",
	)

	return args
}

// parseLine handles one stdout line from zmap: CSV "saddr,sport". The
// header row is filtered defensively even though we pass --no-header-row.
func parseLine(_ context.Context, raw string, emit portscan.LineEmitter) {
	line := portscan.StripCRTail(raw)
	if line == "" || strings.HasPrefix(strings.ToLower(line), "saddr") {
		return
	}

	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		return
	}

	ip, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil || !ip.IsValid() || !ip.Is4() {
		return
	}

	port, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil || port < 1 || port > 65535 {
		return
	}

	emit(portscan.OpenPort{IP: ip, Port: uint16(port)})
}
