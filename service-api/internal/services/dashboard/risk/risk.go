// Package risk answers GET /dashboard/risk: score-bucket distribution and
// top risky services / hosts.
package risk

import (
	"context"

	"golang.org/x/sync/errgroup"

	dashboarddto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/dashboard"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/nullable"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
)

// Config carries the policy knobs that shape what counts as risky.
type Config struct {
	// HostScoreThreshold is the per-service risk score above which a service
	// contributes to its host's "risky" reputation.
	HostScoreThreshold int32
}

// DefaultConfig returns sensible defaults for the risk dashboard.
func DefaultConfig() Config {
	return Config{HostScoreThreshold: 65}
}

// Service answers the risk dashboard endpoint.
type Service struct {
	cfg      Config
	hosts    host.Repository
	services service.Repository
}

// New builds a Service.
func New(cfg Config, hosts host.Repository, services service.Repository) *Service {
	if cfg.HostScoreThreshold <= 0 {
		cfg.HostScoreThreshold = DefaultConfig().HostScoreThreshold
	}

	return &Service{cfg: cfg, hosts: hosts, services: services}
}

// Compute returns the score-bucket distribution, top risky services, and
// top risky hosts in parallel.
func (s *Service) Compute(ctx context.Context, limit uint64) (dashboarddto.RiskResponse, error) {
	var (
		buckets       map[string]uint64
		hostBuckets   map[string]uint64
		riskyServices []service.RiskyService
		riskyHosts    []host.ScoredHost
	)

	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		out, err := s.services.RiskBuckets(groupCtx)
		if err != nil {
			return err
		}

		buckets = out

		return nil
	})

	group.Go(func() error {
		out, err := s.hosts.HostRiskBuckets(groupCtx)
		if err != nil {
			return err
		}

		hostBuckets = out

		return nil
	})

	group.Go(func() error {
		out, err := s.services.TopRiskyServices(groupCtx, limit)
		if err != nil {
			return err
		}

		riskyServices = out

		return nil
	})

	group.Go(func() error {
		out, err := s.hosts.TopHostsByRiskScore(groupCtx, limit)
		if err != nil {
			return err
		}

		riskyHosts = out

		return nil
	})

	if err := group.Wait(); err != nil {
		return dashboarddto.RiskResponse{}, err
	}

	return buildResponse(buckets, hostBuckets, riskyServices, riskyHosts), nil
}

func buildResponse(
	buckets map[string]uint64,
	hostBuckets map[string]uint64,
	riskyServices []service.RiskyService,
	riskyHosts []host.ScoredHost,
) dashboarddto.RiskResponse {
	out := dashboarddto.RiskResponse{
		ScoreBuckets:     make([]dashboarddto.ScoreBucket, 0, len(service.RiskBucketLabels)),
		HostScoreBuckets: make([]dashboarddto.ScoreBucket, 0, len(service.RiskBucketLabels)),
		TopRiskyServices: make([]dashboarddto.RiskyService, 0, len(riskyServices)),
		TopRiskyHosts:    make([]dashboarddto.RiskyHost, 0, len(riskyHosts)),
	}

	for _, label := range service.RiskBucketLabels {
		out.ScoreBuckets = append(out.ScoreBuckets, dashboarddto.ScoreBucket{
			Bucket: label,
			Count:  buckets[label],
		})
		out.HostScoreBuckets = append(out.HostScoreBuckets, dashboarddto.ScoreBucket{
			Bucket: label,
			Count:  hostBuckets[label],
		})
	}

	for _, srv := range riskyServices {
		out.TopRiskyServices = append(out.TopRiskyServices, dashboarddto.RiskyService{
			ServiceID: srv.ServiceID,
			HostIP:    srv.HostIP,
			Port:      srv.Port,
			RiskScore: srv.RiskScore,
			Protocol:  nullable.String(srv.Protocol),
			TopFactor: nullable.String(srv.TopFactor),
		})
	}

	for _, row := range riskyHosts {
		out.TopRiskyHosts = append(out.TopRiskyHosts, dashboarddto.RiskyHost{
			HostID:      row.HostID,
			IP:          row.IP,
			RiskScore:   row.RiskScore,
			CountryCode: nullable.String(row.CountryCode),
			TopFactor:   nullable.String(row.TopFactor),
		})
	}

	return out
}
