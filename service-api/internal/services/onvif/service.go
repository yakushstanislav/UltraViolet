// Package onvif owns ONVIF concurrency limits, response cache, and lab credentials.
package onvif

import (
	"strings"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/onviflabcred"
)

// Service holds ONVIF infrastructure shared by host media handlers.
type Service struct {
	Config         Config
	CommandGate    *CommandGate
	RateLimiter    *rate.Limiter
	ResponseCache  *ResponseCache
	LabCredentials []onviflabcred.Pair
}

// New builds a Service from configuration and optional lab-credential sources.
func New(cfg Config, logger *zap.SugaredLogger) *Service {
	if cfg.Enabled && cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}

	s := &Service{
		Config:        cfg,
		CommandGate:   NewCommandGate(cfg),
		ResponseCache: NewResponseCache(cfg.ResponseCacheTTL),
	}

	if cfg.Enabled && cfg.RateLimitRPS > 0 {
		burst := cfg.RateLimitBurst
		if burst < 1 {
			burst = 1
		}

		s.RateLimiter = rate.NewLimiter(rate.Limit(cfg.RateLimitRPS), burst)
	}

	maxLabPairs := cfg.LabProbeMaxCredentialPairs
	if maxLabPairs < 1 {
		maxLabPairs = 200
	}

	if maxLabPairs > 500 {
		maxLabPairs = 500
	}

	cfg.LabProbeMaxCredentialPairs = maxLabPairs
	s.Config = cfg

	if cfg.LabProbePerAttemptTimeout <= 0 {
		s.Config.LabProbePerAttemptTimeout = defaultLabPerAttemptTimeout
	}

	if cfg.LabProbeInterAttemptDelay <= 0 {
		s.Config.LabProbeInterAttemptDelay = defaultLabInterAttemptDelay
	}

	s.LabCredentials = loadLabCredentials(cfg, maxLabPairs, logger)

	return s
}

func loadLabCredentials(cfg Config, maxPairs int, logger *zap.SugaredLogger) []onviflabcred.Pair {
	path := strings.TrimSpace(cfg.LabProbeCredentialsFile)
	if path != "" {
		pairs, err := onviflabcred.LoadFile(path, maxPairs)
		if err != nil {
			logger.Warnw(
				"Can't read ONVIF lab credentials file, using embedded defaults",
				zap.Error(err),
				zap.String("path", path),
			)
		} else if len(pairs) > 0 {
			return pairs
		}
	}

	pairs, err := onviflabcred.LoadEmbedded(maxPairs)
	if err != nil {
		logger.Warnw("Can't parse embedded ONVIF lab credentials", zap.Error(err))

		return nil
	}

	return pairs
}
