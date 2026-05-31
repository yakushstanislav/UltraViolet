// Package policy loads the v2 risk policy + per-protocol prior table out of
// uv_risk_policy / uv_risk_protocol_prior, caches the result with a TTL, and
// reloads on demand (policy admin endpoints) or on pg_notify.
package policy

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
	riskpolicyrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/riskpolicy"
)

// DefaultCacheTTL is the staleness window for the in-memory policy cache.
const DefaultCacheTTL = 60 * time.Second

// Config controls the policy cache.
type Config struct {
	CacheTTL time.Duration `env:"RISK_POLICY_CACHE_TTL" env-default:"60s"`
}

// DefaultConfig returns the seeded cache TTL.
func DefaultConfig() Config {
	return Config{CacheTTL: DefaultCacheTTL}
}

// Service threads the live policy + protocol prior table to every scoring
// call-site. Constructed once at startup and shared across handlers/workers.
type Service struct {
	cfg                  Config
	riskPolicyRepository riskpolicyrepository.Repository
	logger               *zap.SugaredLogger

	mu       sync.RWMutex
	policy   risk.Policy
	priors   risk.PriorTable
	loadedAt time.Time
	primed   bool
}

// New builds the policy cache backed by riskPolicyRepository.
func New(cfg Config, riskPolicyRepository riskpolicyrepository.Repository, logger *zap.SugaredLogger) *Service {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}

	return &Service{
		cfg:                  cfg,
		riskPolicyRepository: riskPolicyRepository,
		logger:               logger,
		policy:               risk.DefaultPolicy(),
		priors:               risk.DefaultPriors(),
	}
}

// Get returns the cached policy + priors, refreshing in-flight if the TTL has
// expired. Callers should treat the returned values as read-only.
func (s *Service) Get(ctx context.Context) (risk.Policy, risk.PriorTable) {
	if value, table, ok := s.readCached(); ok {
		return value, table
	}

	return s.refresh(ctx)
}

// Invalidate forces the next Get to reload from the database. Call after a
// policy UPDATE so the next recompute reads the new weights instead of the
// cached snapshot.
func (s *Service) Invalidate() {
	s.mu.Lock()
	s.loadedAt = time.Time{}
	s.mu.Unlock()
}

func (s *Service) readCached() (risk.Policy, risk.PriorTable, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.primed {
		return risk.Policy{}, risk.PriorTable{}, false
	}

	if time.Since(s.loadedAt) >= s.cfg.CacheTTL {
		return risk.Policy{}, risk.PriorTable{}, false
	}

	return s.policy, s.priors, true
}

func (s *Service) refresh(ctx context.Context) (risk.Policy, risk.PriorTable) {
	policy, err := s.riskPolicyRepository.GetDefault(ctx)
	if err != nil {
		s.logger.Warnw("Can't reload risk policy, keeping cached value", zap.Error(err))

		return s.fallback()
	}

	priors, err := s.riskPolicyRepository.ListProtocolPriors(ctx)
	if err != nil {
		s.logger.Warnw("Can't reload protocol priors, keeping cached value", zap.Error(err))

		return s.fallback()
	}

	s.mu.Lock()
	s.policy = policy
	s.priors = priors
	s.loadedAt = time.Now()
	s.primed = true
	s.mu.Unlock()

	return policy, priors
}

func (s *Service) fallback() (risk.Policy, risk.PriorTable) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.primed {
		return s.policy, s.priors
	}

	return risk.DefaultPolicy(), risk.DefaultPriors()
}
