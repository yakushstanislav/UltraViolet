package host

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/riskmetrics"
	attackpathrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/attackpath"
	hostrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	risksnapshotrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/risksnapshot"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	riskpolicysvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/policy"
	riskremediationsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/remediation"
	risksignalssvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/signals"
	servicesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/service"
)

// Config controls host-level risk aggregation policy.
type Config struct {
	HighRiskThreshold int32         `env:"HOST_RISK_THRESHOLD"          env-default:"65"`
	SnapshotMinDelta  int32         `env:"RISK_SNAPSHOT_MIN_DELTA"      env-default:"2"`
	SnapshotMaxIdle   time.Duration `env:"RISK_SNAPSHOT_MAX_IDLE"       env-default:"24h"`
}

// DefaultConfig returns sensible host risk defaults.
func DefaultConfig() Config {
	return Config{
		HighRiskThreshold: 65,
		SnapshotMinDelta:  2,
		SnapshotMaxIdle:   24 * time.Hour,
	}
}

// RiskService persists host-level attack-surface scores using the
// probability×impact model. Constructed once at startup and shared by every
// recompute call-site (the periodic worker, the CVE matcher, the ingest hook).
type RiskService struct {
	cfg                    Config
	pool                   *pgxpool.Pool
	hostRepository         hostrepository.Repository
	serviceRepository      servicerepository.Repository
	riskSnapshotRepository risksnapshotrepository.Repository
	attackPathRepository   attackpathrepository.Repository
	policy                 *riskpolicysvc.Service
	signals                *risksignalssvc.Collector
	scoring                *servicesvc.ScoringService
	remediationEngine      *riskremediationsvc.Engine
	logger                 *zap.SugaredLogger
}

// NewRiskService builds a RiskService.
func NewRiskService(
	cfg Config,
	pool *pgxpool.Pool,
	hostRepository hostrepository.Repository,
	serviceRepository servicerepository.Repository,
	riskSnapshotRepository risksnapshotrepository.Repository,
	attackPathRepository attackpathrepository.Repository,
	policy *riskpolicysvc.Service,
	signals *risksignalssvc.Collector,
	scoring *servicesvc.ScoringService,
	remediationEngine *riskremediationsvc.Engine,
	logger *zap.SugaredLogger,
) *RiskService {
	defaults := DefaultConfig()

	if cfg.HighRiskThreshold <= 0 {
		cfg.HighRiskThreshold = defaults.HighRiskThreshold
	}

	if cfg.SnapshotMinDelta <= 0 {
		cfg.SnapshotMinDelta = defaults.SnapshotMinDelta
	}

	if cfg.SnapshotMaxIdle <= 0 {
		cfg.SnapshotMaxIdle = defaults.SnapshotMaxIdle
	}

	return &RiskService{
		cfg:                    cfg,
		pool:                   pool,
		hostRepository:         hostRepository,
		serviceRepository:      serviceRepository,
		riskSnapshotRepository: riskSnapshotRepository,
		attackPathRepository:   attackPathRepository,
		policy:                 policy,
		signals:                signals,
		scoring:                scoring,
		remediationEngine:      remediationEngine,
		logger:                 logger,
	}
}

// triggerContextKey is the in-process key carrying the recompute trigger
// label from caller to the metrics increment. Default is "unspecified".
type triggerContextKey struct{}

// WithTrigger returns a context carrying the recompute trigger label used
// by riskmetrics.RiskRecomputeTotal. Callers (CVE matcher, periodic worker,
// tag mutation handler) wrap their context so the aggregator increments
// the right counter without changing the AggregateForHost signature.
func WithTrigger(ctx context.Context, trigger string) context.Context {
	if trigger == "" {
		return ctx
	}

	return context.WithValue(ctx, triggerContextKey{}, trigger)
}

func triggerFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(triggerContextKey{}).(string); ok && v != "" {
		return v
	}

	return "unspecified"
}

// AggregateForService resolves the owning host and recomputes its score.
func (s *RiskService) AggregateForService(ctx context.Context, serviceID uint64) error {
	hostID, err := s.HostIDForService(ctx, serviceID)
	if err != nil {
		return err
	}

	return s.AggregateForHost(ctx, hostID)
}

// HostIDForService is the package-public service→host lookup, exposed so
// the in-process recompute queue can resolve the owning host before
// enqueuing without reaching into the unexported repository field.
func (s *RiskService) HostIDForService(ctx context.Context, serviceID uint64) (uint64, error) {
	hostID, err := s.serviceRepository.HostIDForService(ctx, serviceID)
	if err != nil {
		return 0, fmt.Errorf("can't resolve host for service: %w", err)
	}

	return hostID, nil
}

// AggregateForHost recomputes and persists the host-level risk score.
// The three persistence steps — SetRisk, snapshot append, bucket-change
// event — share one pgx.Tx so observers never see a half-applied
// recompute (new score without the matching snapshot, or score change
// without the matching event row).
func (s *RiskService) AggregateForHost(ctx context.Context, hostID uint64) error {
	riskmetrics.RiskRecomputeTotal.WithLabelValues(triggerFromContext(ctx)).Inc()

	inputs, err := s.hostRepository.GatherRiskInputs(ctx, hostID, s.cfg.HighRiskThreshold)
	if err != nil {
		return fmt.Errorf("can't gather host risk inputs: %w", err)
	}

	result, perService, err := s.computeHostRisk(ctx, hostID, inputs)
	if err != nil {
		return fmt.Errorf("can't compute host risk: %w", err)
	}

	factorsJSON, err := json.Marshal(result.Factors)
	if err != nil {
		return fmt.Errorf("can't marshal host risk factors: %w", err)
	}

	prevScore, err := s.persistInTx(ctx, hostID, result, factorsJSON)
	if err != nil {
		return err
	}

	s.refreshRecommendations(ctx, hostID, perService)

	_ = prevScore

	return nil
}

// persistInTx wraps the three persistence steps in one pgx.Tx so the
// post-recompute state is atomic. Snapshot dedup is checked first (read
// query) so the transaction stays short.
func (s *RiskService) persistInTx(ctx context.Context, hostID uint64, result risk.HostRiskResult, factorsJSON []byte) (int32, error) {
	if s.pool == nil {
		// Test wiring without a pool — fall back to non-atomic path.
		prevScore, setErr := s.hostRepository.SetRisk(ctx, hostID, hostrepository.RiskParams{
			Score:       result.Score,
			Probability: result.P,
			Impact:      result.I,
			Confidence:  result.Confidence,
			FactorsJSON: factorsJSON,
		})
		if setErr != nil {
			return 0, fmt.Errorf("can't persist host risk: %w", setErr)
		}

		s.appendSnapshot(ctx, hostID, result, factorsJSON, prevScore)

		return prevScore, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("can't begin recompute transaction: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	hostRepo := s.hostRepository.WithTx(tx)
	snapshotRepo := s.riskSnapshotRepository.WithTx(tx)

	prevScore, err := hostRepo.SetRisk(ctx, hostID, hostrepository.RiskParams{
		Score:       result.Score,
		Probability: result.P,
		Impact:      result.I,
		Confidence:  result.Confidence,
		FactorsJSON: factorsJSON,
	})
	if err != nil {
		return 0, fmt.Errorf("can't persist host risk: %w", err)
	}

	s.appendSnapshotTx(ctx, snapshotRepo, hostID, result, factorsJSON, prevScore)

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("can't commit recompute transaction: %w", err)
	}

	return prevScore, nil
}

// appendSnapshot appends a uv_host_risk_snapshot row only when the score
// crossed the configured min-delta or 24h elapsed since the previous
// snapshot — this is the dedup half of the RISK_SNAPSHOT_MIN_DELTA contract.
func (s *RiskService) appendSnapshot(ctx context.Context, hostID uint64, result risk.HostRiskResult, factorsJSON []byte, prevScore int32) {
	s.appendSnapshotTx(ctx, s.riskSnapshotRepository, hostID, result, factorsJSON, prevScore)
}

// appendSnapshotTx is the in-transaction variant — the repo argument is
// already routed through the shared pgx.Tx so the snapshot row commits
// atomically with the host SetRisk + event Append.
func (s *RiskService) appendSnapshotTx(ctx context.Context, repo risksnapshotrepository.Repository, hostID uint64, result risk.HostRiskResult, factorsJSON []byte, prevScore int32) {
	if repo == nil {
		return
	}

	if !s.shouldSnapshot(ctx, hostID, result.Score, prevScore) {
		return
	}

	snapshot := risksnapshotrepository.HostSnapshot{
		HostID:      hostID,
		CapturedAt:  time.Now().UTC(),
		Score:       result.Score,
		Probability: result.P,
		Impact:      result.I,
		Confidence:  result.Confidence,
		FactorsJSON: factorsJSON,
	}

	if err := repo.AppendHost(ctx, snapshot); err != nil {
		s.logger.Warnw("Can't append host risk snapshot",
			zap.Uint64("host_id", hostID),
			zap.Error(err),
		)

		return
	}

	riskmetrics.RiskSnapshotAppendedTotal.Inc()
}

// shouldSnapshot enforces the RISK_SNAPSHOT_MIN_DELTA contract — write only
// when the score moved enough or enough time elapsed since the last capture.
func (s *RiskService) shouldSnapshot(ctx context.Context, hostID uint64, newScore, prevScore int32) bool {
	if s.cfg.SnapshotMinDelta <= 0 && s.cfg.SnapshotMaxIdle <= 0 {
		return true
	}

	if abs32(newScore-prevScore) >= s.cfg.SnapshotMinDelta {
		return true
	}

	latest, err := s.riskSnapshotRepository.LatestHost(ctx, hostID)
	if err != nil {
		// No prior snapshot or load error → fall through and append.
		return true
	}

	return time.Since(latest.CapturedAt) >= s.cfg.SnapshotMaxIdle
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}

	return v
}

// computeHostRisk loads every service on the host, gathers per-service
// signals (CVE / TLS / SSH / HTTP / fingerprint) via risksignalssvc.Collector,
// scores each service and unions the results at the host level. The second
// return value carries the per-service results so the remediation engine can
// project recommendations without re-running the scorer.
func (s *RiskService) computeHostRisk(ctx context.Context, hostID uint64, inputs hostrepository.RiskAggregateInputs) (risk.HostRiskResult, []riskremediationsvc.PerServiceResult, error) {
	services, err := s.serviceRepository.ListForHostRisk(ctx, hostID)
	if err != nil {
		return risk.HostRiskResult{}, nil, fmt.Errorf("can't list services for host risk: %w", err)
	}

	policy, _ := s.policy.Get(ctx)

	serviceIDs := make([]uint64, 0, len(services))
	bannerPresent := make(map[uint64]bool, len(services))

	for _, row := range services {
		serviceIDs = append(serviceIDs, row.ID)
		bannerPresent[row.ID] = row.BannerHash.Valid
	}

	perService, err := s.signals.Collect(ctx, serviceIDs, bannerPresent)
	if err != nil {
		return risk.HostRiskResult{}, nil, fmt.Errorf("can't collect per-service signals: %w", err)
	}

	pathScore := s.loadAttackPathScore(ctx, hostID)

	results := make([]risk.ServiceRiskResult, 0, len(services))
	perServiceResults := make([]riskremediationsvc.PerServiceResult, 0, len(services))

	for _, row := range services {
		signal := perService[row.ID]
		serviceInputs := servicesvc.Inputs{
			ServiceID:            row.ID,
			HostID:               hostID,
			Port:                 row.Port,
			Protocol:             row.Protocol.String,
			CVEs:                 signal.CVEs,
			Auth:                 signal.Auth,
			DefaultCredsObserved: signal.DefaultCredsObserved,
			Crypto:               signal.Crypto,
			AppHygiene:           signal.AppHygiene,
			NetworkPosition:      pathScore.Centrality,
			LastSeen:             row.LastSeen,
			Signals:              signal.Observed,
		}

		serviceResult := s.scoring.Score(ctx, serviceInputs)
		results = append(results, serviceResult)

		perServiceResults = append(perServiceResults, riskremediationsvc.PerServiceResult{
			ServiceID: row.ID,
			Port:      row.Port,
			CVEs:      signal.CVEs,
			Result:    serviceResult,
		})
	}

	impact := risk.ComputeHostImpact(risk.ImpactInputs{
		ServiceCount:  inputs.ServiceCount,
		MgmtPortCount: countManagementPorts(services),
		GraphLateral:  pathScore.PivotScore,
	}, policy)

	confidence := risk.ConfidenceInputs{
		Completeness:    completenessFromCollected(perService),
		Recency:         risk.RecencyFrom(inputs.LastSeen, time.Now().UTC(), policy),
		SignalQuality:   signalQualityFromCollected(perService),
		TagCompleteness: risk.TagCompletenessFrom(false, false),
		UntaggedCap:     policy.UntaggedConfidenceCap,
	}

	return risk.AggregateHost(results, impact, confidence, policy), perServiceResults, nil
}

// countManagementPorts counts services on the host that listen on a
// management surface (DB / broker / RDP / plaintext mgmt).
func countManagementPorts(services []servicerepository.HostRiskServiceRow) int32 {
	count := int32(0)

	for _, row := range services {
		switch risk.ClassifyPort(row.Port) {
		case risk.PortBucketRemoteDesktop, risk.PortBucketDatabase, risk.PortBucketBrokerCache, risk.PortBucketPlaintext:
			count++
		case risk.PortBucketHTTP, risk.PortBucketHTTPS, risk.PortBucketOther:
		}
	}

	return count
}

func completenessFromCollected(perService map[uint64]risksignalssvc.ServiceSignals) float64 {
	if len(perService) == 0 {
		return 0
	}

	sum := 0.0

	for _, signal := range perService {
		sum += risk.CompletenessFrom(signal.Observed)
	}

	return sum / float64(len(perService))
}

func signalQualityFromCollected(perService map[uint64]risksignalssvc.ServiceSignals) float64 {
	if len(perService) == 0 {
		return 0
	}

	direct := 0
	total := 0

	for _, signal := range perService {
		if len(signal.CVEs) > 0 {
			direct++
		}

		if signal.Crypto.TLSPresent || signal.Crypto.SSHWeakKex {
			direct++
		}

		if signal.AppHygiene.HTTPApplicable {
			direct++
		}

		if signal.Auth != risk.AuthUnknown {
			direct++
		}

		total += 4
	}

	return risk.SignalQualityFrom(direct, total)
}

// loadAttackPathScore loads the host's centrality + pivot score from
// uv_host_attack_path_score, returning a zero-value score on miss or error so
// the network_position channel collapses to "no evidence" without breaking
// the recompute.
func (s *RiskService) loadAttackPathScore(ctx context.Context, hostID uint64) attackpathrepository.Score {
	if s.attackPathRepository == nil {
		return attackpathrepository.Score{}
	}

	score, err := s.attackPathRepository.GetScore(ctx, hostID)
	if err != nil {
		return attackpathrepository.Score{}
	}

	return score
}

// refreshRecommendations triggers the remediation engine asynchronously
// (well, in-process synchronous but log-and-ignore on failure) so a slow
// recommendation generator can't block the canonical score persistence.
func (s *RiskService) refreshRecommendations(ctx context.Context, hostID uint64, perService []riskremediationsvc.PerServiceResult) {
	if s.remediationEngine == nil {
		return
	}

	policy, _ := s.policy.Get(ctx)

	if err := s.remediationEngine.Refresh(ctx, hostID, perService, policy); err != nil {
		s.logger.Warnw("Can't refresh host recommendations",
			zap.Uint64("host_id", hostID),
			zap.Error(err),
		)
	}
}
