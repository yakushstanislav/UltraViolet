package onvif

import "time"

// Config controls ONVIF command endpoints and lab credential probing.
type Config struct {
	Enabled             bool          `env:"ONVIF_COMMAND_ENABLED" env-default:"true"`
	MaxConcurrent       int           `env:"ONVIF_COMMAND_MAX_CONCURRENT" env-default:"8"`
	RequestTimeout      time.Duration `env:"ONVIF_COMMAND_TIMEOUT" env-default:"15s"`
	RateLimitRPS        float64       `env:"ONVIF_COMMAND_RATE_LIMIT_RPS" env-default:"5"`
	RateLimitBurst      int           `env:"ONVIF_COMMAND_RATE_LIMIT_BURST" env-default:"20"`
	ResponseCacheTTL    time.Duration `env:"ONVIF_RESPONSE_CACHE_TTL" env-default:"0s"`
	RTSPSnapshotEnabled bool          `env:"ONVIF_RTSP_SNAPSHOT_ENABLED" env-default:"true"`
	// LabCredentialProbeEnabled allows POST .../onvif-lab-credential-probe (off by default).
	LabCredentialProbeEnabled bool `env:"ONVIF_LAB_CREDENTIAL_PROBE_ENABLED" env-default:"false"`
	// LabProbeCredentialsFile overrides embedded defaults (UTF-8 text, one user:password per line, # comments).
	LabProbeCredentialsFile string `env:"ONVIF_LAB_CREDENTIALS_FILE" env-default:""`
	// LabProbeMaxCredentialPairs caps parsed pairs from file or embedded list (1–500).
	LabProbeMaxCredentialPairs int `env:"ONVIF_LAB_CREDENTIAL_MAX_PAIRS" env-default:"200"`
	// LabProbePerAttemptTimeout bounds each HTTP attempt during a lab probe.
	LabProbePerAttemptTimeout time.Duration `env:"ONVIF_LAB_PER_ATTEMPT_TIMEOUT" env-default:"6s"`
	// LabProbeInterAttemptDelay is the pause between probe attempts to the device.
	LabProbeInterAttemptDelay time.Duration `env:"ONVIF_LAB_INTER_ATTEMPT_DELAY" env-default:"100ms"`
}
