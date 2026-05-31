// Package masscan wraps the masscan CLI for SYN port discovery (scan mode masscan).
package masscan

// Config is loaded from the environment (flat keys; used under uv-scanner's
// nested scanner.Config by cleanenv).
//
// Recommended Docker: CAP_NET_RAW + CAP_NET_ADMIN, privileged masscan binary
// (setcap), libpcap.so symlink in image; avoid MASSCAN_UNPRIVILEGED on Alpine.
//
// Variables:
//
//	MASSCAN_BINARY          masscan executable (default: masscan)
//	MASSCAN_RATE            --rate, packets per second (default: 3000)
//	MASSCAN_RETRIES         --retries, extra SYN sends per port to compensate
//	                        packet loss on intermediate gear (default: 2; 0 disables)
//	MASSCAN_WAIT_SECONDS    --wait, seconds to collect replies after send (default: 30; 0 = aggressive)
//	MASSCAN_INTERFACE       optional -e iface (e.g. eth0 in Docker)
//	MASSCAN_UNPRIVILEGED    --unprivileged (default: false)
type Config struct {
	Binary       string `env:"MASSCAN_BINARY"          env-default:"masscan"`
	RatePerSec   int    `env:"MASSCAN_RATE"            env-default:"3000"`
	Retries      int    `env:"MASSCAN_RETRIES"         env-default:"2"`
	WaitSeconds  int    `env:"MASSCAN_WAIT_SECONDS"    env-default:"30"`
	Interface    string `env:"MASSCAN_INTERFACE"       env-default:""`
	Unprivileged bool   `env:"MASSCAN_UNPRIVILEGED"    env-default:"false"`
}
