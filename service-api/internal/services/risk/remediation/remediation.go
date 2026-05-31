// Package remediation generates and persists the ordered list of operator
// actions the risk service believes would reduce a host's score the most.
package remediation

import (
	"context"
	"fmt"
	"sort"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/remediation"
)

// MaxPerHost caps the number of recommendations the engine will emit per
// host so the dashboard stays scannable.
const MaxPerHost = 20

// PerServiceResult bundles the service id, its scoring result and the
// inputs that produced it so the engine can hand them to the per-service
// candidate generator.
type PerServiceResult struct {
	ServiceID uint64
	Port      uint16
	CVEs      []risk.CVEInput
	Result    risk.ServiceRiskResult
}

// Engine emits recommendations for one host. Constructed once at startup
// (no per-call state).
type Engine struct {
	repository remediation.Repository
}

// New builds an Engine.
func New(repository remediation.Repository) *Engine {
	return &Engine{repository: repository}
}

// Refresh regenerates the open-recommendation set for a host.
func (e *Engine) Refresh(ctx context.Context, hostID uint64, services []PerServiceResult, policy risk.Policy) error {
	candidates := make([]remediation.Recommendation, 0, MaxPerHost)

	for _, svc := range services {
		for _, cand := range risk.RecommendForService(svc.ServiceID, svc.Port, svc.CVEs, svc.Result.Probability) {
			candidates = append(candidates, recommendationFromCandidate(hostID, svc, cand, policy))
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].ExpectedDeltaScore > candidates[j].ExpectedDeltaScore
	})

	if len(candidates) > MaxPerHost {
		candidates = candidates[:MaxPerHost]
	}

	if err := e.repository.ReplaceForHost(ctx, hostID, candidates); err != nil {
		return fmt.Errorf("can't persist host recommendations: %w", err)
	}

	return nil
}

// TopForHost returns the persisted open recommendations.
func (e *Engine) TopForHost(ctx context.Context, hostID, limit uint64) ([]remediation.Recommendation, error) {
	return e.repository.TopForHost(ctx, hostID, limit)
}

func recommendationFromCandidate(hostID uint64, svc PerServiceResult, cand risk.RecommendationCandidate, policy risk.Policy) remediation.Recommendation {
	serviceRef := svc.ServiceID

	return remediation.Recommendation{
		HostID:             hostID,
		ServiceID:          &serviceRef,
		ActionCode:         cand.ActionCode,
		Label:              cand.Label,
		ExpectedDeltaP:     cand.ExpectedDeltaP,
		ExpectedDeltaScore: projectedScoreDrop(svc.Result.Probability.P, cand.ExpectedDeltaP, policy.KCoefficient),
	}
}

// projectedScoreDrop estimates how many score points the recommendation
// would shave by recomputing the per-service mapping 100·(1-exp(-k·P)) at
// the original P and at the lowered P. The delta is clamped at zero so
// negative numbers never reach the UI.
func projectedScoreDrop(originalP, deltaP, k float64) int32 {
	if deltaP <= 0 || originalP <= 0 {
		return 0
	}

	lowered := originalP - deltaP
	if lowered < 0 {
		lowered = 0
	}

	before := risk.ScoreFromExponent(k * originalP)
	after := risk.ScoreFromExponent(k * lowered)

	delta := before - after
	if delta < 0 {
		return 0
	}

	return delta
}
