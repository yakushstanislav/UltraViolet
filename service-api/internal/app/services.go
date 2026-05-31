package app

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/countryprefix"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/geoip"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanpolicy"
	alertsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/alert"
	auditsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/audit"
	authsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/auth"
	cvesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/cve"
	risksvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/dashboard/risk"
	summarysvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/dashboard/summary"
	topologysvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/dashboard/topology"
	trendssvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/dashboard/trends"
	deltasvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/delta"
	hostsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/host"
	onvifsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/onvif"
	pivotsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/pivot"
	riskfacadesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk"
	riskpolicysvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/policy"
	riskremediationsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/remediation"
	risksignalssvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/signals"
	rtspsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/rtsp"
	savedsearchsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/savedsearch"
	scansvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scan"
	scanschedulesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scanschedule"
	searchsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/search"
	servicerisksvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/service"
	usersvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/user"
)

// Dashboard groups the four sub-services that back the /v1/dashboard/* API.
type Dashboard struct {
	Summary  *summarysvc.Service
	Trends   *trendssvc.Service
	Topology *topologysvc.Service
	Risk     *risksvc.Service
}

// Services aggregates every domain service constructed at startup and shared
// by the HTTP handler.
type Services struct {
	Auth         *authsvc.Service
	User         *usersvc.Service
	Dashboard    Dashboard
	Host         *hostsvc.Service
	Scan         *scansvc.Service
	ScanSchedule *scanschedulesvc.Service
	Search       *searchsvc.Service
	CVE          *cvesvc.Service
	Audit        *auditsvc.Service
	Alert        *alertsvc.Service
	Delta        *deltasvc.Service
	SavedSearch  *savedsearchsvc.Service
	ONVIF        *onvifsvc.Service
	RTSP         *rtspsvc.Service
	Pivot        *pivotsvc.Service
	HostRisk     *hostsvc.RiskService
	Risk         *riskfacadesvc.Service
}

// ServicesConfig carries the cross-cutting service configuration.
type ServicesConfig struct {
	Auth       auth.Config
	ScanPolicy scanpolicy.Config
	GeoIP      geoip.Config
	Risk       risksvc.Config
	HostRisk   hostsvc.Config
	RiskPolicy riskpolicysvc.Config
	CVE        cvesvc.Config
	ONVIF      onvifsvc.Config
	RTSP       rtspsvc.Config
}

// NewServices builds every domain service from the shared repository aggregate.
func NewServices(pool *pgxpool.Pool, repos *Repositories, cfg ServicesConfig, logger *zap.SugaredLogger) *Services {
	countryIndex := buildCountryPrefixIndex(cfg.GeoIP, logger)

	scanService := scansvc.NewService(repos.Scan, cfg.ScanPolicy, countryIndex)
	riskPolicyService := riskpolicysvc.New(cfg.RiskPolicy, repos.RiskPolicy, logger)
	riskSignalsCollector := risksignalssvc.New(
		repos.HTTPResponse,
		repos.HTTPSecurity,
		repos.TLSCertificate,
		repos.SSHInfo,
		repos.ServiceFingerprint,
		repos.CVEMatch,
	)
	serviceScoringService := servicerisksvc.NewScoringService(riskPolicyService)
	remediationEngine := riskremediationsvc.New(repos.Remediation)
	hostRiskService := hostsvc.NewRiskService(
		cfg.HostRisk,
		pool,
		repos.Host,
		repos.Service,
		repos.RiskSnapshot,
		repos.AttackPath,
		riskPolicyService,
		riskSignalsCollector,
		serviceScoringService,
		remediationEngine,
		logger,
	)

	return &Services{
		Auth: authsvc.NewService(repos.User, repos.RefreshToken, cfg.Auth),
		User: usersvc.NewService(repos.User, repos.RefreshToken, logger),
		Dashboard: Dashboard{
			Summary: summarysvc.New(
				repos.Host,
				repos.Service,
				repos.Scan,
				repos.SavedSearch,
				repos.Delta,
				repos.Alert,
				repos.CVEMatch,
			),
			Trends:   trendssvc.New(repos.Scan, repos.Host, repos.Delta),
			Topology: topologysvc.New(repos.Host, repos.Service, repos.TLSCertificate),
			Risk:     risksvc.New(cfg.Risk, repos.Host, repos.Service),
		},
		Host: hostsvc.NewService(
			repos.Host,
			repos.Service,
			repos.HTTPResponse,
			repos.HTTPScreenshot,
			repos.HTTPSecurity,
			repos.TLSCertificate,
			repos.ServiceFingerprint,
			repos.SSHInfo,
			repos.SMTPInfo,
			repos.DNS,
			repos.CVEMatch,
			repos.RiskSnapshot,
			cfg.HostRisk.HighRiskThreshold,
		),
		Scan:         scanService,
		ScanSchedule: scanschedulesvc.NewService(repos.ScanSchedule, scanService),
		Search:       searchsvc.NewService(repos.Search),
		CVE:          cvesvc.New(repos.CVECatalog, repos.CVEMatch, repos.CVESyncState, cfg.CVE),
		Audit:        auditsvc.NewService(repos.Audit),
		Alert:        alertsvc.NewService(repos.Alert),
		Delta:        deltasvc.NewService(repos.Delta),
		SavedSearch:  savedsearchsvc.NewService(repos.SavedSearch),
		ONVIF:        onvifsvc.New(cfg.ONVIF, logger),
		RTSP:         rtspsvc.New(cfg.RTSP),
		Pivot:        pivotsvc.New(repos.Pivot),
		HostRisk:     hostRiskService,
		Risk: riskfacadesvc.New(
			repos.Host,
			repos.Service,
			repos.AttackPath,
			repos.Remediation,
			repos.RiskPolicy,
			riskPolicyService,
			riskSignalsCollector,
		),
	}
}

// buildCountryPrefixIndex opens the configured GeoIP country database and
// returns a country → IPv4 prefixes index used by the scan service to
// validate country-strategy requests. It returns nil (with a warning logged)
// when the database is missing or the build fails — the validator then
// rejects country scans with a clear error rather than failing startup.
func buildCountryPrefixIndex(cfg geoip.Config, logger *zap.SugaredLogger) *countryprefix.Index {
	geoDB, err := geoip.Open(&cfg)
	if err != nil {
		logger.Warnw("Can't open GeoIP database for country scan validation", zap.Error(err))

		return nil
	}

	defer geoDB.Close()

	index, err := geoDB.BuildCountryPrefixIndex()
	if err != nil {
		logger.Warnw("Can't build country prefix index", zap.Error(err))

		return nil
	}

	if index == nil {
		logger.Infow("No GeoIP country database configured; country-strategy scans will be rejected")

		return nil
	}

	logger.Infow("Built country prefix index for scan validation",
		zap.Int("countries", index.Len()),
		zap.Int("ipv4_prefixes", index.PrefixCount()),
	)

	return index
}
