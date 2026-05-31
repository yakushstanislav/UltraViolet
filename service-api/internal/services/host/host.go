// Package host enriches host records with protocol-level detail.
package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"go.uber.org/zap"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/risk"
	cvematch "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	dnsrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/dns"
	hostrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	httpresponserepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpresponse"
	httpscreenshotrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpscreenshot"
	httpsecurityrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpsecurity"
	risksnapshotrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/risksnapshot"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	servicefingerprintrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/servicefingerprint"
	smtpinforepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/smtpinfo"
	sshinforepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/sshinfo"
	tlscertificaterepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/tlscertificate"
)

// Service loads host records enriched with per-service protocol metadata.
type Service struct {
	hostRepository               hostrepository.Repository
	serviceRepository            servicerepository.Repository
	httpResponseRepository       httpresponserepository.Repository
	httpScreenshotRepository     httpscreenshotrepository.Repository
	httpSecurityRepository       httpsecurityrepository.Repository
	tlsCertificateRepository     tlscertificaterepository.Repository
	serviceFingerprintRepository servicefingerprintrepository.Repository
	sshInfoRepository            sshinforepository.Repository
	smtpInfoRepository           smtpinforepository.Repository
	dnsRepository                dnsrepository.Repository
	cveMatchRepository           cvematch.Repository
	riskSnapshotRepository       risksnapshotrepository.Repository
	highRiskThreshold            int32
}

// NewService creates a new Service with the given repositories.
func NewService(
	hostRepository hostrepository.Repository,
	serviceRepository servicerepository.Repository,
	httpResponseRepository httpresponserepository.Repository,
	httpScreenshotRepository httpscreenshotrepository.Repository,
	httpSecurityRepository httpsecurityrepository.Repository,
	tlsCertificateRepository tlscertificaterepository.Repository,
	serviceFingerprintRepository servicefingerprintrepository.Repository,
	sshInfoRepository sshinforepository.Repository,
	smtpInfoRepository smtpinforepository.Repository,
	dnsRepository dnsrepository.Repository,
	cveMatchRepository cvematch.Repository,
	riskSnapshotRepository risksnapshotrepository.Repository,
	highRiskThreshold int32,
) *Service {
	if highRiskThreshold <= 0 {
		highRiskThreshold = DefaultHighRiskThreshold()
	}

	return &Service{
		hostRepository:               hostRepository,
		serviceRepository:            serviceRepository,
		httpResponseRepository:       httpResponseRepository,
		httpScreenshotRepository:     httpScreenshotRepository,
		httpSecurityRepository:       httpSecurityRepository,
		tlsCertificateRepository:     tlsCertificateRepository,
		serviceFingerprintRepository: serviceFingerprintRepository,
		sshInfoRepository:            sshInfoRepository,
		smtpInfoRepository:           smtpInfoRepository,
		dnsRepository:                dnsRepository,
		cveMatchRepository:           cveMatchRepository,
		riskSnapshotRepository:       riskSnapshotRepository,
		highRiskThreshold:            highRiskThreshold,
	}
}

// DefaultHighRiskThreshold matches HOST_RISK_THRESHOLD default.
func DefaultHighRiskThreshold() int32 { return 65 }

// Ping verifies the database connection.
func (s *Service) Ping(ctx context.Context) error {
	_, err := s.hostRepository.Count(ctx)

	return err
}

// HTTPScreenshot returns the rendered thumbnail for the given service when it
// belongs to the host with the given IP. Surfaces pgkit.ErrNoRows when no
// thumbnail exists yet so callers can return 404.
func (s *Service) HTTPScreenshot(ctx context.Context, ip netip.Addr, serviceID uint64) (*httpscreenshotrepository.Screenshot, error) {
	return s.httpScreenshotRepository.GetByHostIPAndServiceID(ctx, ip, serviceID)
}

// RelatedByIP returns one page of peer hosts that share a TLS fingerprint,
// JARM hash, or favicon with the given IP, along with the total match count.
func (s *Service) RelatedByIP(ctx context.Context, ip netip.Addr, page, limit uint64) (hostdto.RelatedHostsResponse, error) {
	rows, total, err := s.hostRepository.RelatedByIP(ctx, ip, page, limit)
	if err != nil {
		return hostdto.RelatedHostsResponse{}, err
	}

	items := make([]hostdto.RelatedHost, 0, len(rows))
	for _, row := range rows {
		items = append(items, hostdto.RelatedHost{
			IP:          row.IP,
			Reason:      row.Reason,
			Value:       row.Value,
			CountryCode: row.CountryCode,
		})
	}

	return hostdto.RelatedHostsResponse{
		Items: items,
		Page:  page,
		Limit: limit,
		Total: total,
	}, nil
}

// RiskExplain returns the persisted host score plus the full
// probability×impact breakdown stored in uv_host.risk_factors.
func (s *Service) RiskExplain(ctx context.Context, ip netip.Addr) (hostdto.RiskExplainResponse, error) {
	hostRecord, err := s.hostRepository.GetByIP(ctx, ip)
	if err != nil {
		return hostdto.RiskExplainResponse{}, err
	}

	inputs, err := s.hostRepository.GatherRiskInputs(ctx, hostRecord.ID, s.highRiskThreshold)
	if err != nil {
		return hostdto.RiskExplainResponse{}, err
	}

	resp := hostdto.RiskExplainResponse{
		IP:          hostRecord.IP.String(),
		RiskScore:   hostRecord.RiskScore,
		Probability: hostRecord.Probability,
		Impact:      hostRecord.Impact,
		Confidence:  hostRecord.Confidence,
		Bucket:      risk.BucketForScore(hostRecord.RiskScore),
		Components: hostdto.RiskExplainComponents{
			MaxServiceRisk:       inputs.MaxServiceRisk,
			ServiceCount:         inputs.ServiceCount,
			HighRiskServiceCount: inputs.HighRiskServiceCount,
			KEVCount:             inputs.KEVCount,
			CriticalCVECount:     inputs.CriticalCVECount,
			LastSeen:             inputs.LastSeen.Format(time.RFC3339),
		},
	}

	if inputs.MaxEPSS.Valid {
		v := inputs.MaxEPSS.Float64
		resp.Components.MaxEPSS = &v
	}

	if len(hostRecord.RiskFactors) > 0 {
		// Legacy [{"code","label","weight"}] rows decode to the zero-value
		// risk.Factors (no channels/impacts), so the explain endpoint still
		// returns 200 with the legacy `factors` chip list populated by the
		// enrichment path and the new channels/impacts arrays empty. The
		// decode error is logged at warn so a corrupt row is observable
		// without 5xx-ing the page.
		var factors risk.Factors

		if unmarshalErr := json.Unmarshal(hostRecord.RiskFactors, &factors); unmarshalErr != nil {
			logger.UnpackContext(ctx).Warnw("Falling back to legacy host risk factors",
				zap.String("ip", ip.String()),
				zap.Error(unmarshalErr),
			)
		}

		resp.Channels = make([]hostdto.RiskExplainChannel, 0, len(factors.Channels))
		for _, channel := range factors.Channels {
			resp.Channels = append(resp.Channels, hostdto.RiskExplainChannel{
				Code:    channel.Code,
				Label:   channel.Label,
				P:       channel.P,
				Sources: channel.Sources,
			})
		}

		resp.Impacts = make([]hostdto.RiskExplainImpact, 0, len(factors.Impacts))
		for _, impact := range factors.Impacts {
			resp.Impacts = append(resp.Impacts, hostdto.RiskExplainImpact{
				Code:         impact.Code,
				Label:        impact.Label,
				Weight:       impact.Weight,
				Contribution: impact.Contribution,
			})
		}

		resp.ConfidenceMeters = hostdto.RiskExplainConfidence{
			Completeness:    factors.ConfidenceMeters.Completeness,
			Recency:         factors.ConfidenceMeters.Recency,
			SignalQuality:   factors.ConfidenceMeters.SignalQuality,
			TagCompleteness: factors.ConfidenceMeters.TagCompleteness,
		}
	}

	if hostRecord.RiskUpdatedAt.Valid {
		resp.UpdatedAt = hostRecord.RiskUpdatedAt.Time.Format(time.RFC3339)
	}

	return resp, nil
}

// RiskHistory returns the host's score timeline within the supplied window.
// limit caps the row count; days clamps the lookback (defaults applied by the
// handler so the service stays parameter-free for the dashboard path).
func (s *Service) RiskHistory(ctx context.Context, ip netip.Addr, since time.Time, limit uint64) (hostdto.RiskHistoryResponse, error) {
	hostRecord, err := s.hostRepository.GetByIP(ctx, ip)
	if err != nil {
		return hostdto.RiskHistoryResponse{}, err
	}

	snapshots, err := s.riskSnapshotRepository.ListHost(ctx, hostRecord.ID, since, time.Time{}, limit)
	if err != nil {
		return hostdto.RiskHistoryResponse{}, fmt.Errorf("can't list host snapshots: %w", err)
	}

	points := make([]hostdto.RiskHistoryPoint, 0, len(snapshots))

	for _, snapshot := range snapshots {
		points = append(points, hostdto.RiskHistoryPoint{
			CapturedAt:  snapshot.CapturedAt.Format(time.RFC3339),
			Score:       snapshot.Score,
			Probability: snapshot.Probability,
			Impact:      snapshot.Impact,
			Confidence:  snapshot.Confidence,
		})
	}

	return hostdto.RiskHistoryResponse{
		IP:     hostRecord.IP.String(),
		Points: points,
	}, nil
}
