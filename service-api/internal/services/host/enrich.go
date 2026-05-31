package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/nullable"
	cvematch "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	dnsrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/dns"
	httpresponserepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpresponse"
	httpsecurityrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/httpsecurity"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	servicefingerprintrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/servicefingerprint"
	smtpinforepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/smtpinfo"
	sshinforepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/sshinfo"
	tlscertificaterepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/tlscertificate"
)

// enrichment holds the per-service maps populated by loadEnrichment for one
// GetByIP call.
type enrichment struct {
	httpByService         map[uint64]*httpresponserepository.HTTPResponse
	httpSecurityByService map[uint64]*httpsecurityrepository.HTTPSecurity
	screenshotByService   map[uint64]bool
	tlsByService          map[uint64]*tlscertificaterepository.TLSCertificate
	chainByService        map[uint64][]tlscertificaterepository.TLSChainNode
	tlsFindingsByService  map[uint64][]tlscertificaterepository.TLSFinding
	fingerprintByService  map[uint64][]*servicefingerprintrepository.Fingerprint
	sshByService          map[uint64]*sshinforepository.SSHInfo
	smtpByService         map[uint64]*smtpinforepository.SMTPInfo
	dnsRecords            []dnsrepository.Record
	cveByService          map[uint64][]cvematch.Detail
	cveCountsByService    map[uint64]cvematch.SeverityCounts
}

// GetByIP returns a host record with enriched service data for the given IP.
func (s *Service) GetByIP(ctx context.Context, ip netip.Addr, page, limit, offset uint64) (hostdto.Host, error) {
	hostRecord, err := s.hostRepository.GetByIP(ctx, ip)
	if err != nil {
		return hostdto.Host{}, err
	}

	services, total, err := s.serviceRepository.GetByHostID(ctx, hostRecord.ID, limit, offset)
	if err != nil {
		return hostdto.Host{}, err
	}

	dtoHost := hostdto.Host{
		ID:        hostRecord.ID,
		IP:        hostRecord.IP.String(),
		FirstSeen: hostRecord.FirstSeen.Format(time.RFC3339),
		LastSeen:  hostRecord.LastSeen.Format(time.RFC3339),
		Page:      page,
		Limit:     limit,
		Total:     total,
	}

	dtoHost.CountryCode = nullable.StringValue(hostRecord.CountryCode)
	dtoHost.CountryName = nullable.StringValue(hostRecord.CountryName)
	dtoHost.City = nullable.StringValue(hostRecord.City)
	dtoHost.Latitude = hostRecord.Latitude
	dtoHost.Longitude = hostRecord.Longitude
	dtoHost.ASN = hostRecord.ASN
	dtoHost.ASNOrg = nullable.StringValue(hostRecord.ASNOrg)
	dtoHost.PtrHostname = nullable.StringValue(hostRecord.PtrHostname)
	dtoHost.RiskScore = int(hostRecord.RiskScore)

	if len(hostRecord.RiskFactors) > 0 {
		chips, decodeErr := decodeHostRiskFactorsChips(hostRecord.RiskFactors)
		if decodeErr != nil {
			logger.UnpackContext(ctx).Warnw("Unrecognised host risk factors payload",
				zap.String("ip", ip.String()),
				zap.Error(decodeErr),
			)
		}

		dtoHost.RiskFactors = chips
	}

	if hostRecord.RiskUpdatedAt.Valid {
		dtoHost.RiskUpdatedAt = hostRecord.RiskUpdatedAt.Time.Format(time.RFC3339)
	}

	serviceIDs := make([]uint64, 0, len(services))
	for _, service := range services {
		serviceIDs = append(serviceIDs, service.ID)
	}

	enriched, err := s.loadEnrichment(ctx, hostRecord.ID, serviceIDs)
	if err != nil {
		return hostdto.Host{}, err
	}

	for _, r := range enriched.dnsRecords {
		dtoHost.DNS = append(dtoHost.DNS, hostdto.DNSRecord{
			Type:             r.RecordType,
			Name:             r.Name,
			Value:            r.Value,
			Source:           r.Source,
			ForwardConfirmed: r.ForwardConfirmed,
			CapturedAt:       r.CapturedAt.Format(time.RFC3339),
		})
	}

	for _, service := range services {
		dtoHost.Services = append(dtoHost.Services, s.buildServiceDTO(service, enriched))
	}

	return dtoHost, nil
}

// loadEnrichment fans out to all auxiliary repositories in parallel and
// returns the collected per-service maps.
func (s *Service) loadEnrichment(ctx context.Context, hostID uint64, serviceIDs []uint64) (enrichment, error) {
	var out enrichment

	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		res, err := s.httpResponseRepository.GetByServiceIDs(groupCtx, serviceIDs)
		if err != nil {
			return fmt.Errorf("list HTTP responses: %w", err)
		}

		out.httpByService = res

		return nil
	})

	group.Go(func() error {
		res, err := s.tlsCertificateRepository.GetByServiceIDs(groupCtx, serviceIDs)
		if err != nil {
			return fmt.Errorf("list TLS certificates: %w", err)
		}

		out.tlsByService = res

		return nil
	})

	group.Go(func() error {
		res, err := s.tlsCertificateRepository.GetChainByServiceIDs(groupCtx, serviceIDs)
		if err != nil {
			return fmt.Errorf("list TLS chains: %w", err)
		}

		out.chainByService = res

		return nil
	})

	group.Go(func() error {
		res, err := s.tlsCertificateRepository.GetFindingsByServiceIDs(groupCtx, serviceIDs)
		if err != nil {
			return fmt.Errorf("list TLS findings: %w", err)
		}

		out.tlsFindingsByService = res

		return nil
	})

	if s.httpSecurityRepository != nil {
		group.Go(func() error {
			res, err := s.httpSecurityRepository.GetByServiceIDs(groupCtx, serviceIDs)
			if err != nil {
				return fmt.Errorf("list HTTP security: %w", err)
			}

			out.httpSecurityByService = res

			return nil
		})
	}

	if s.httpScreenshotRepository != nil {
		group.Go(func() error {
			res, err := s.httpScreenshotRepository.HasScreenshotByServiceIDs(groupCtx, serviceIDs)
			if err != nil {
				return fmt.Errorf("list HTTP screenshots: %w", err)
			}

			out.screenshotByService = res

			return nil
		})
	}

	group.Go(func() error {
		res, err := s.serviceFingerprintRepository.GetByServiceIDs(groupCtx, serviceIDs)
		if err != nil {
			return fmt.Errorf("list service fingerprints: %w", err)
		}

		out.fingerprintByService = res

		return nil
	})

	group.Go(func() error {
		res, err := s.sshInfoRepository.GetByServiceIDs(groupCtx, serviceIDs)
		if err != nil {
			return fmt.Errorf("list SSH info: %w", err)
		}

		out.sshByService = res

		return nil
	})

	group.Go(func() error {
		res, err := s.smtpInfoRepository.GetByServiceIDs(groupCtx, serviceIDs)
		if err != nil {
			return fmt.Errorf("list SMTP info: %w", err)
		}

		out.smtpByService = res

		return nil
	})

	group.Go(func() error {
		res, err := s.dnsRepository.ListByHostID(groupCtx, hostID)
		if err != nil {
			return fmt.Errorf("list dns records: %w", err)
		}

		out.dnsRecords = res

		return nil
	})

	if s.cveMatchRepository != nil {
		group.Go(func() error {
			res, err := s.cveMatchRepository.ListByServiceIDs(groupCtx, serviceIDs)
			if err != nil {
				return fmt.Errorf("list service cves: %w", err)
			}

			out.cveByService = res

			return nil
		})

		group.Go(func() error {
			res, err := s.cveMatchRepository.CountsByServiceIDs(groupCtx, serviceIDs)
			if err != nil {
				return fmt.Errorf("count service cves: %w", err)
			}

			out.cveCountsByService = res

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return enrichment{}, fmt.Errorf("enrich host services: %w", err)
	}

	return out, nil
}

// buildServiceDTO converts a repository service row into the wire DTO and
// merges in any matched enrichment data for that service.
func (s *Service) buildServiceDTO(service *servicerepository.Service, e enrichment) hostdto.Service {
	dtoService := hostdto.Service{
		ID:        service.ID,
		Port:      service.Port,
		Transport: string(service.Transport),
		LastSeen:  service.LastSeen.Format(time.RFC3339),
	}

	tlsCert := e.tlsByService[service.ID]
	httpResp := e.httpByService[service.ID]
	sshInfo := e.sshByService[service.ID]
	components := e.fingerprintByService[service.ID]
	fp := primaryFingerprint(components)

	score, factors := enrichRiskScore(service.RiskScore, service.RiskFactors, tlsCert, httpResp, sshInfo, fp)
	dtoService.RiskScore = score
	dtoService.RiskFactors = factors

	if service.Protocol.Valid {
		dtoService.Protocol = service.Protocol.String
	}

	if service.Banner.Valid {
		dtoService.Banner = service.Banner.String
	}

	if service.BannerHash.Valid {
		dtoService.BannerHash = service.BannerHash.String
	}

	if httpResp != nil {
		dtoService.HTTP = httpResponseToDTO(httpResp)

		if sec, ok := e.httpSecurityByService[service.ID]; ok {
			dtoService.HTTP.SecurityInfo = httpSecurityToDTO(sec)
		}

		if e.screenshotByService[service.ID] {
			dtoService.HTTP.HasScreenshot = true
		}
	}

	if tlsCert != nil {
		dtoService.TLS = tlsCertToDTO(tlsCert)

		if chain, ok := e.chainByService[service.ID]; ok {
			dtoService.TLS.Chain = tlsChainToDTO(chain)
		}

		if findings, ok := e.tlsFindingsByService[service.ID]; ok {
			dtoService.TLS.Findings = tlsFindingsToDTO(findings)
		}
	}

	if fp != nil {
		dtoService.Fingerprint = serviceFingerprintToDTO(fp)
	}

	if len(components) > 0 {
		dtoService.Fingerprints = serviceFingerprintsToDTO(components)
	}

	if sshInfo != nil {
		dtoService.SSH = sshInfoToDTO(sshInfo)
	}

	if smtpInfo, ok := e.smtpByService[service.ID]; ok {
		dtoService.SMTP = smtpInfoToDTO(smtpInfo)
	}

	if cves, ok := e.cveByService[service.ID]; ok && len(cves) > 0 {
		dtoService.CVEs = cveMatchesToDTO(cves)
	}

	if counts, ok := e.cveCountsByService[service.ID]; ok && hasCVEs(counts) {
		dtoService.CVESummary = &hostdto.CVESummary{
			Critical: counts.Critical,
			High:     counts.High,
			Medium:   counts.Medium,
			Low:      counts.Low,
		}
	}

	return dtoService
}

// decodeHostRiskFactorsChips projects the JSONB blob in uv_host.risk_factors
// into the legacy []RiskFactor chip list shown on the host page header. The
// column has two historical shapes: the original [{"code","label","weight"}]
// array and the new probability×impact object ({"channels":[{"label","p"}]}).
// The object shape is the one written today by the risk aggregator; the
// fallback keeps older rows usable. A row whose JSON matches neither shape
// surfaces as an empty chip list and an error so the caller can warn.
func decodeHostRiskFactorsChips(raw []byte) ([]hostdto.RiskFactor, error) {
	var legacy []hostdto.RiskFactor
	if err := json.Unmarshal(raw, &legacy); err == nil {
		return legacy, nil
	}

	var modern struct {
		Channels []struct {
			Code  string  `json:"code"`
			Label string  `json:"label"`
			P     float64 `json:"p"`
		} `json:"channels"`
	}

	if err := json.Unmarshal(raw, &modern); err != nil {
		return nil, fmt.Errorf("can't decode host risk factors as legacy or modern shape: %w", err)
	}

	out := make([]hostdto.RiskFactor, 0, len(modern.Channels))
	for _, channel := range modern.Channels {
		if channel.Label == "" {
			continue
		}

		out = append(out, hostdto.RiskFactor{
			Code:   channel.Code,
			Label:  channel.Label,
			Weight: int32(channel.P * 100),
		})
	}

	return out, nil
}
