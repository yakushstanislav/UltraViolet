package app

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cverisk"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/nvd"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanpolicy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/scanner"
	cvesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/cve"
	hostsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/host"
	scansvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scan"
	scanschedulesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scanschedule"
	screenshotsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/screenshot"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/alert"
	attackpathworker "github.com/yakushstanislav/UltraViolet/service-api/internal/worker/attackpath"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/cancel"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/cvematch"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/cveriskenrich"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/cvesync"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/hostriskaggregate"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/pause"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/queue"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/recovery"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/retention"
	risksnapshotworker "github.com/yakushstanislav/UltraViolet/service-api/internal/worker/risksnapshot"
	scanscheduleworker "github.com/yakushstanislav/UltraViolet/service-api/internal/worker/scanschedule"
	screenshotworker "github.com/yakushstanislav/UltraViolet/service-api/internal/worker/screenshot"
)

// ScannerWorkerConfig controls queue polling for uv-scanner worker mode.
type ScannerWorkerConfig struct {
	PollInterval           time.Duration `env:"SCANNER_WORKER_POLL_INTERVAL"     env-default:"1s"`
	BackgroundPollInterval time.Duration `env:"SCANNER_BACKGROUND_POLL_INTERVAL" env-default:"30s"`
	RunningTTL             time.Duration `env:"SCANNER_RUNNING_TTL"              env-default:"1h"`
}

// ScannerWorkersConfig groups scanner worker tuning and feature configs.
type ScannerWorkersConfig struct {
	Worker           ScannerWorkerConfig
	Retention        retention.Config
	NVD              nvd.Config
	CVESync          cvesync.Config
	CVEMatcher       cvesvc.MatcherConfig
	CVEMatch         cvematch.Config
	CVERisk          cveriskenrich.Config
	CVERiskClient    cverisk.Config
	ScanPolicy       scanpolicy.Config
	ScanSchedule     scanscheduleworker.Config
	Screenshot       screenshotsvc.Config
	ScreenshotWorker screenshotworker.Config
	HostRisk         hostriskaggregate.Config
	RecomputeQueue   hostsvc.RecomputeQueueConfig
	RiskSnapshot     risksnapshotworker.Config
	AttackPath       attackpathworker.Config
}

// ScannerWorkers holds declaratively registered periodic jobs for uv-scanner.
type ScannerWorkers struct {
	Hot        []worker.Job
	Background []worker.Job
}

// NewScannerWorkers builds hot and background job lists for the scanner worker mode.
func NewScannerWorkers(
	cfg ScannerWorkersConfig,
	pool *pgxpool.Pool,
	repos *Repositories,
	pipeline *scanner.Pipeline,
	cveMatcher *cvesvc.Matcher,
	hostRiskAggregator *hostsvc.RiskService,
	cancelListener *cancel.Listener,
	pauseListener *pause.Listener,
	logger *zap.SugaredLogger,
) *ScannerWorkers {
	nvdClient := nvd.New(cfg.NVD)
	riskClient := cverisk.New(cfg.CVERiskClient)
	scanService := scansvc.NewService(repos.Scan, cfg.ScanPolicy, pipeline.CountryPrefixIndex())
	scheduleService := scanschedulesvc.NewService(repos.ScanSchedule, scanService)
	screenshotService := screenshotsvc.New(cfg.Screenshot)

	background := []worker.Job{
		alert.New(repos.Alert, repos.Search, logger),
		retention.New(pool, cfg.Retention, logger),
		cvesync.New(cfg.CVESync, nvdClient, repos.CVECatalog, repos.CVESyncState, logger),
		cvematch.New(cfg.CVEMatch, pool, repos.CVECatalog, cveMatcher, logger),
		cveriskenrich.New(cfg.CVERisk, riskClient, repos.CVECatalog, logger),
		hostriskaggregate.New(cfg.HostRisk, repos.Host, hostRiskAggregator, logger),
		risksnapshotworker.New(cfg.RiskSnapshot, repos.RiskSnapshot, repos.Remediation, logger),
		attackpathworker.New(cfg.AttackPath, pool, repos.AttackPath, logger),
		scanscheduleworker.New(cfg.ScanSchedule, repos.ScanSchedule, scheduleService, logger),
	}

	if cfg.Screenshot.Enabled {
		background = append(background, screenshotworker.New(
			pool,
			repos.HTTPScreenshot,
			screenshotService,
			cfg.ScreenshotWorker,
			logger,
		))
	}

	return &ScannerWorkers{
		Hot: []worker.Job{
			recovery.NewStaleRunningJob(repos.Scan, cfg.Worker.RunningTTL, logger),
			recovery.NewAbandonedCancelJob(repos.Scan, logger),
			queue.New(repos.Scan, repos.Delta, pipeline, cancelListener, pauseListener, logger),
		},
		Background: background,
	}
}
