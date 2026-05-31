package probe

import "time"

// Config controls probe timeouts and body limits applied across all
// protocol probers.
type Config struct {
	Timeout       time.Duration `env:"PROBE_TIMEOUT"         env-default:"10s"`
	BannerTimeout time.Duration `env:"PROBE_BANNER_TIMEOUT"  env-default:"2s"`
	MaxBody       int           `env:"PROBE_MAX_BODY_BYTES"  env-default:"262144"`
	JARMEnabled   bool          `env:"PROBE_JARM_ENABLED"    env-default:"true"`
	UserAgent     string        `env:"PROBE_USER_AGENT"      env-default:"UltraViolet/1.0"`
}
