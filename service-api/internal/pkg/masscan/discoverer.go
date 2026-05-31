package masscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/portscan"
)

// New builds a Discoverer that executes the masscan CLI. The returned type
// satisfies portscan.Discoverer (CIDR mode) and additionally exposes
// DiscoverIPs for the random strategy (pre-materialised IP list).
func New(cfg Config) *Discoverer {
	return &Discoverer{cfg: cfg}
}

// Discoverer wraps the masscan CLI invocation.
type Discoverer struct {
	cfg Config
}

// Discover validates the input and launches masscan via the shared
// Subprocess scaffolding, parsing its line-delimited JSON output.
func (d *Discoverer) Discover(ctx context.Context, cidr string, ports []uint16) (*portscan.Stream, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("can't parse CIDR for masscan: %w", err)
	}

	if !prefix.Addr().Is4() {
		return nil, errors.New("masscan mode supports IPv4 targets only")
	}

	portSpec := portscan.FormatPortSpec(ports)
	if portSpec == "" {
		return nil, errors.New("masscan requires at least one port")
	}

	return portscan.Subprocess{
		Name:      "masscan",
		Binary:    binaryOrDefault(d.cfg.Binary),
		Args:      buildArgs(d.cfg, cidr, portSpec),
		ParseLine: parseLine,
	}.Run(ctx)
}

// DiscoverIPs runs masscan against a pre-materialised list of IPv4
// targets passed via -iL. The IPs are written to an OS temp file that is
// unlinked immediately after the subprocess starts — masscan holds the
// open fd, so the inode survives until the process exits.
func (d *Discoverer) DiscoverIPs(ctx context.Context, ips []netip.Addr, ports []uint16) (*portscan.Stream, error) {
	if len(ips) == 0 {
		return nil, errors.New("masscan requires at least one IP target")
	}

	portSpec := portscan.FormatPortSpec(ports)
	if portSpec == "" {
		return nil, errors.New("masscan requires at least one port")
	}

	for _, ip := range ips {
		if !ip.Is4() {
			return nil, errors.New("masscan mode supports IPv4 targets only")
		}
	}

	path, err := portscan.WriteIPListFile("uv-masscan-targets-*.txt", ips)
	if err != nil {
		return nil, err
	}

	stream, err := portscan.Subprocess{
		Name:      "masscan",
		Binary:    binaryOrDefault(d.cfg.Binary),
		Args:      buildArgsIPList(d.cfg, path, portSpec),
		ParseLine: parseLine,
	}.Run(ctx)
	if err != nil {
		_ = os.Remove(path)

		return nil, err
	}

	// Subprocess.Run has spawned the process and the kernel keeps the open
	// fd alive even after we unlink — safe to drop the directory entry now.
	_ = os.Remove(path)

	return stream, nil
}

func binaryOrDefault(bin string) string {
	if bin == "" {
		return "masscan"
	}

	return bin
}

func buildArgs(cfg Config, cidr, portSpec string) []string {
	rate := cfg.RatePerSec
	if rate <= 0 {
		rate = 3000
	}

	wait := cfg.WaitSeconds
	if wait < 0 {
		wait = 0
	}

	retries := cfg.Retries
	if retries < 0 {
		retries = 0
	}

	args := make([]string, 0, 18)

	if iface := strings.TrimSpace(cfg.Interface); iface != "" {
		args = append(args, "-e", iface)
	}

	args = append(args,
		cidr,
		"-p"+portSpec,
		"--rate="+strconv.Itoa(rate),
		"--retries="+strconv.Itoa(retries),
		"-oJ", "-",
		"--wait", strconv.Itoa(wait),
	)

	if cfg.Unprivileged {
		args = append([]string{"--unprivileged"}, args...)
	}

	return args
}

// buildArgsIPList builds the masscan argv for the random strategy: targets
// come from -iL <file> instead of a positional CIDR. All other flags
// (rate, retries, output format, wait, interface, --unprivileged) are
// identical to buildArgs.
func buildArgsIPList(cfg Config, listPath, portSpec string) []string {
	rate := cfg.RatePerSec
	if rate <= 0 {
		rate = 3000
	}

	wait := cfg.WaitSeconds
	if wait < 0 {
		wait = 0
	}

	retries := cfg.Retries
	if retries < 0 {
		retries = 0
	}

	args := make([]string, 0, 18)

	if iface := strings.TrimSpace(cfg.Interface); iface != "" {
		args = append(args, "-e", iface)
	}

	args = append(args,
		"-iL", listPath,
		"-p"+portSpec,
		"--rate="+strconv.Itoa(rate),
		"--retries="+strconv.Itoa(retries),
		"-oJ", "-",
		"--wait", strconv.Itoa(wait),
	)

	if cfg.Unprivileged {
		args = append([]string{"--unprivileged"}, args...)
	}

	return args
}

// jsonRecord matches masscan's --output-format json/JSONL document shape.
type jsonRecord struct {
	IP    string     `json:"ip"`
	Ports []jsonPort `json:"ports"`
}

type jsonPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// parseLine handles one stdout line from masscan: either a JSON object,
// a JSON array, the array brackets, or interleaved progress noise.
func parseLine(ctx context.Context, raw string, emit portscan.LineEmitter) {
	line := portscan.StripCRTail(raw)

	line = strings.TrimSpace(strings.TrimPrefix(line, ","))
	if line == "" || line == "[" || line == "]" {
		return
	}

	if strings.HasPrefix(line, "[") {
		var batch []jsonRecord

		if err := json.Unmarshal([]byte(line), &batch); err == nil {
			for i := range batch {
				emitRecord(ctx, &batch[i], emit)
			}
		}

		return
	}

	if !strings.HasPrefix(line, "{") {
		return
	}

	var rec jsonRecord

	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return
	}

	emitRecord(ctx, &rec, emit)
}

func emitRecord(_ context.Context, rec *jsonRecord, emit portscan.LineEmitter) {
	ip, err := netip.ParseAddr(rec.IP)
	if err != nil || !ip.IsValid() {
		return
	}

	for _, p := range rec.Ports {
		if !portLooksOpen(p) {
			continue
		}

		emit(portscan.OpenPort{IP: ip, Port: uint16(p.Port)})
	}
}

func portLooksOpen(p jsonPort) bool {
	if p.Port < 1 || p.Port > 65535 {
		return false
	}

	if p.Proto != "" && !strings.EqualFold(p.Proto, "tcp") {
		return false
	}

	status := strings.ToLower(strings.TrimSpace(p.Status))
	if status == "closed" || status == "filtered" {
		return false
	}

	if status == "open" || strings.HasPrefix(status, "open|") {
		return true
	}

	reason := strings.ToLower(p.Reason)

	return strings.Contains(reason, "syn-ack") || strings.Contains(reason, "synack")
}
