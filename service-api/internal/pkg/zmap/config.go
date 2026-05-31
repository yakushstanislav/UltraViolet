// Package zmap wraps the ZMap CLI for fast SYN discovery (scan mode zmap).
package zmap

// Config is loaded from the environment (flat keys; used under uv-scanner's
// nested scanner.Config by cleanenv).
//
// Recommended Docker: CAP_NET_RAW + CAP_NET_ADMIN, setcap on the zmap binary;
// see deploy/Dockerfile alongside masscan.
//
// Variables:
//
//	ZMAP_BINARY             zmap executable (default: zmap)
//	ZMAP_RATE               send rate in probes/sec, -r (default: 1000)
//	ZMAP_COOLDOWN_SECONDS   -c cooldown after last probe (default: 8)
//	ZMAP_INTERFACE          optional -i iface (e.g. eth0 in Docker)
type Config struct {
	Binary          string `env:"ZMAP_BINARY"             env-default:"zmap"`
	RatePerSec      int    `env:"ZMAP_RATE"               env-default:"1000"`
	CooldownSeconds int    `env:"ZMAP_COOLDOWN_SECONDS"   env-default:"8"`
	Interface       string `env:"ZMAP_INTERFACE"          env-default:""`
}
