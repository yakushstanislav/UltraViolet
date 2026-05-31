package scan

import (
	"math"
	"math/big"
	"net/netip"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmode"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/targetstrategy"
	scanrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
)

// ComputeProgress returns completion ratio 0..1, or nil when indeterminate.
//
// Slow-engine scans (the only mode with a per-IP target emitter) advance the
// "emitted_targets" counter in stats; that is the numerator. The denominator
// is the CIDR host count for sequential scans or HostLimit for random scans.
//
// Masscan/zmap engines scan the whole CIDR atomically via subprocess and have
// no per-IP progress signal, so this returns nil and the frontend hides the
// bar for those modes.
func ComputeProgress(scanJob *scanrepository.Scan) *float64 {
	mode := scanJob.Mode
	if mode == "" {
		mode = string(scanmode.Slow)
	}

	if mode != string(scanmode.Slow) {
		return nil
	}

	emitted := emittedFromStats(scanJob.Stats)

	strategy := scanJob.TargetStrategy
	if strategy == "" {
		strategy = string(targetstrategy.Sequential)
	}

	var total uint64

	switch strategy {
	case string(targetstrategy.Sequential):
		if !scanJob.CIDR.Valid || scanJob.CIDR.String == "" {
			return nil
		}

		total = cidrHostCount(scanJob.CIDR.String)

	case string(targetstrategy.Random):
		if !scanJob.HostLimit.Valid || scanJob.HostLimit.Int64 <= 0 {
			return nil
		}

		total = uint64(scanJob.HostLimit.Int64)

	default:
		return nil
	}

	if total == 0 {
		return nil
	}

	p := float64(emitted) / float64(total)
	if p > 1 {
		p = 1
	}

	return &p
}

func emittedFromStats(stats map[string]any) uint64 {
	if stats == nil {
		return 0
	}

	switch n := stats["emitted_targets"].(type) {
	case float64:
		if n < 0 {
			return 0
		}

		return uint64(n)
	case int64:
		if n < 0 {
			return 0
		}

		return uint64(n)
	case uint64:
		return n
	default:
		return 0
	}
}

func cidrHostCount(cidr string) uint64 {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0
	}

	ones := prefix.Bits()
	bits := prefix.Addr().BitLen()

	if ones < 0 || ones > bits {
		return 0
	}

	hostBits := bits - ones
	if hostBits >= 64 {
		return math.MaxUint64
	}

	if prefix.Addr().Is4() && ones <= 30 {
		// Usable host count for typical IPv4 scans (exclude network/broadcast for /31-/32 edge cases simplified).
		n := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
		if n.Sign() > 0 && n.Uint64() > 2 && ones < 31 {
			return n.Uint64() - 2
		}

		return n.Uint64()
	}

	return new(big.Int).Lsh(big.NewInt(1), uint(hostBits)).Uint64()
}

// EnrichStatsHostsScanned copies hosts_scanned into the stats map for chip rendering.
func EnrichStatsHostsScanned(stats map[string]any, hostsScanned uint64) map[string]any {
	if stats == nil {
		stats = make(map[string]any)
	}

	stats["hosts_scanned"] = hostsScanned

	return stats
}
