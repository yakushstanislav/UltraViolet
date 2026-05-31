// Package risk is the application-layer facade for risk-domain queries that
// don't belong on a specific resource (events feed, remediation
// recommendations, policy CRUD, alert-rule CRUD). Per-host queries live on
// services/host.
package risk

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/attackpath"
	hostrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/remediation"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/riskpolicy"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	riskpolicysvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/policy"
	risksignalssvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/signals"
)

// AttackPathView bundles the host's persisted centrality and the relation
// edges anchored on it for /v1/attack-paths/{ip}.
type AttackPathView struct {
	IP        string
	Score     attackpath.Score
	Hosts     map[uint64]string
	Relations []attackpath.Relation
}

// Service is the entry point for /v1/risk/* endpoints.
type Service struct {
	hostRepository        hostrepository.Repository
	serviceRepository     servicerepository.Repository
	attackPathRepository  attackpath.Repository
	remediationRepository remediation.Repository
	riskPolicyRepository  riskpolicy.Repository
	policy                *riskpolicysvc.Service
	signals               *risksignalssvc.Collector
}

// New builds a Service.
func New(
	hostRepository hostrepository.Repository,
	serviceRepository servicerepository.Repository,
	attackPathRepository attackpath.Repository,
	remediationRepository remediation.Repository,
	riskPolicyRepository riskpolicy.Repository,
	policy *riskpolicysvc.Service,
	signals *risksignalssvc.Collector,
) *Service {
	return &Service{
		hostRepository:        hostRepository,
		serviceRepository:     serviceRepository,
		attackPathRepository:  attackPathRepository,
		remediationRepository: remediationRepository,
		riskPolicyRepository:  riskPolicyRepository,
		policy:                policy,
		signals:               signals,
	}
}

// GetAttackPath returns the centrality row and the relation edges for the
// host identified by ip. A missing centrality row collapses to zero — the
// host is in the dataset but the graph worker hasn't computed it yet.
func (s *Service) GetAttackPath(ctx context.Context, ip netip.Addr) (AttackPathView, error) {
	hostRecord, err := s.hostRepository.GetByIP(ctx, ip)
	if err != nil {
		return AttackPathView{}, err
	}

	score, err := s.attackPathRepository.GetScore(ctx, hostRecord.ID)
	if err != nil && !errors.Is(err, attackpath.ErrNotFound) {
		return AttackPathView{}, fmt.Errorf("can't load attack path score: %w", err)
	}

	score.HostID = hostRecord.ID

	relations, err := s.attackPathRepository.ListRelationsForHost(ctx, hostRecord.ID)
	if err != nil {
		return AttackPathView{}, fmt.Errorf("can't list attack path relations: %w", err)
	}

	hostIDs := map[uint64]struct{}{
		hostRecord.ID: {},
	}

	for _, relation := range relations {
		hostIDs[relation.SrcHostID] = struct{}{}
		hostIDs[relation.DstHostID] = struct{}{}
	}

	ids := make([]uint64, 0, len(hostIDs))
	for id := range hostIDs {
		ids = append(ids, id)
	}

	hostIPs, err := s.hostRepository.ListIPsByIDs(ctx, ids)
	if err != nil {
		return AttackPathView{}, fmt.Errorf("can't list attack path host ips: %w", err)
	}

	return AttackPathView{
		IP:        hostRecord.IP.String(),
		Score:     score,
		Hosts:     hostIPs,
		Relations: relations,
	}, nil
}

// ServiceExplainView is the per-service probability breakdown used by
// GET /v1/services/{id}/risk-explain.
type ServiceExplainView struct {
	ServiceID     uint64
	HostID        uint64
	Port          uint16
	Protocol      string
	Probability   float64
	RecencyFactor float64
	Channels      []risk.Channel
}

// ServiceRiskExplain re-runs the per-service probability scorer for one
// service and returns the channel breakdown without persisting anything.
func (s *Service) ServiceRiskExplain(ctx context.Context, serviceID uint64) (ServiceExplainView, error) {
	hostID, err := s.serviceRepository.HostIDForService(ctx, serviceID)
	if err != nil {
		return ServiceExplainView{}, err
	}

	rows, err := s.serviceRepository.ListForHostRisk(ctx, hostID)
	if err != nil {
		return ServiceExplainView{}, fmt.Errorf("can't list host services: %w", err)
	}

	var row *servicerepository.HostRiskServiceRow

	for i := range rows {
		if rows[i].ID == serviceID {
			row = &rows[i]

			break
		}
	}

	if row == nil {
		return ServiceExplainView{}, fmt.Errorf("can't find service %d on host %d", serviceID, hostID)
	}

	bannerPresent := map[uint64]bool{serviceID: row.BannerHash.Valid}

	signalMap, err := s.signals.Collect(ctx, []uint64{serviceID}, bannerPresent)
	if err != nil {
		return ServiceExplainView{}, fmt.Errorf("can't collect signals: %w", err)
	}

	pathScore, _ := s.attackPathRepository.GetScore(ctx, hostID)
	policy, priors := s.policy.Get(ctx)
	signal := signalMap[serviceID]

	probability := risk.ComputeServiceProbability(risk.ServiceProbabilityInputs{
		ServiceID:            serviceID,
		Port:                 row.Port,
		Protocol:             row.Protocol.String,
		CVEs:                 signal.CVEs,
		Auth:                 signal.Auth,
		DefaultCredsObserved: signal.DefaultCredsObserved,
		Crypto:               signal.Crypto,
		AppHygiene:           signal.AppHygiene,
		NetworkPosition:      pathScore.Centrality,
		LastSeen:             row.LastSeen,
		Now:                  time.Now().UTC(),
	}, priors, policy)

	return ServiceExplainView{
		ServiceID:     serviceID,
		HostID:        hostID,
		Port:          row.Port,
		Protocol:      row.Protocol.String,
		Probability:   probability.P,
		RecencyFactor: probability.RecencyFactor,
		Channels:      probability.Channels,
	}, nil
}

// RecommendationsView bundles the host's IP with its open recommendations
// so the handler can map the result to its DTO without juggling separate
// return values.
type RecommendationsView struct {
	IP              string
	Recommendations []remediation.Recommendation
}

// ListRecommendations returns the open recommendations for the host
// identified by ip, ordered by expected score reduction. Identical
// `patch_cve` rows for the same CVE on different services collapse into
// one entry — the operator sees "Patch CVE-X (3 services)" rather than
// three duplicate rows. Non-CVE actions (auth/crypto/headers/port) are
// per-service inherently and pass through untouched.
func (s *Service) ListRecommendations(ctx context.Context, ip netip.Addr, limit uint64) (RecommendationsView, error) {
	hostRecord, err := s.hostRepository.GetByIP(ctx, ip)
	if err != nil {
		return RecommendationsView{}, err
	}

	recs, err := s.remediationRepository.TopForHost(ctx, hostRecord.ID, limit)
	if err != nil {
		return RecommendationsView{}, fmt.Errorf("can't load recommendations: %w", err)
	}

	return RecommendationsView{
		IP:              hostRecord.IP.String(),
		Recommendations: dedupeRecommendations(recs),
	}, nil
}

// dedupeRecommendations collapses duplicate `patch_cve` rows that share
// the same CVE id across multiple services. The combined row keeps the
// **maximum** expected_delta_score / expected_delta_p (patching the same
// CVE once fixes it everywhere) and lists the affected service count in
// its label.
func dedupeRecommendations(recs []remediation.Recommendation) []remediation.Recommendation {
	type cveAggregate struct {
		first        int
		serviceCount int
	}

	seen := make(map[string]*cveAggregate, len(recs))
	out := make([]remediation.Recommendation, 0, len(recs))

	for _, rec := range recs {
		if rec.ActionCode != "patch_cve" {
			out = append(out, rec)

			continue
		}

		cveID := cveIDFromLabel(rec.Label)
		if cveID == "" {
			out = append(out, rec)

			continue
		}

		if agg, ok := seen[cveID]; ok {
			agg.serviceCount++

			// Keep the maximum delta across services — patching a
			// shared library fixes every instance at once.
			if rec.ExpectedDeltaScore > out[agg.first].ExpectedDeltaScore {
				out[agg.first].ExpectedDeltaScore = rec.ExpectedDeltaScore
			}

			if rec.ExpectedDeltaP > out[agg.first].ExpectedDeltaP {
				out[agg.first].ExpectedDeltaP = rec.ExpectedDeltaP
			}

			out[agg.first].Label = "Patch " + cveID + " (" + strconv.Itoa(agg.serviceCount) + " services)"

			continue
		}

		seen[cveID] = &cveAggregate{first: len(out), serviceCount: 1}
		out = append(out, rec)
	}

	return out
}

// cveIDFromLabel extracts the CVE id from a "Patch CVE-2024-12345" label.
// Falls back to "" when the label does not have the canonical shape.
func cveIDFromLabel(label string) string {
	const prefix = "Patch "
	if len(label) <= len(prefix) {
		return ""
	}

	rest := label[len(prefix):]
	for i, r := range rest {
		if r == ' ' {
			return rest[:i]
		}
	}

	return rest
}

// GetPolicy returns the singleton default policy.
func (s *Service) GetPolicy(ctx context.Context) (risk.Policy, error) {
	return s.riskPolicyRepository.GetDefault(ctx)
}

// UpdatePolicy overwrites the singleton default policy and invalidates the
// in-process cache so the next recompute reads the new values.
func (s *Service) UpdatePolicy(ctx context.Context, policy risk.Policy) (risk.Policy, error) {
	if err := s.riskPolicyRepository.Update(ctx, policy); err != nil {
		return risk.Policy{}, err
	}

	s.policy.Invalidate()

	return s.riskPolicyRepository.GetDefault(ctx)
}
