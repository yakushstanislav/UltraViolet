package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/app"
	metricsserver "github.com/yakushstanislav/UltraViolet/service-api/internal/metrics-server"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/banner"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cveseed"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/envsecret"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/ingest"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/poolmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/postgresql"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmode"
	scanrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/scanner"
	cvesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/cve"
	hostsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/host"
	riskpolicysvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/policy"
	riskremediationsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/remediation"
	risksignalssvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/risk/signals"
	servicerisksvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/service"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/cancel"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/worker/pause"
)

const (
	commandScan   = "scan"
	commandWorker = "worker"
)

// Config is the root scanner configuration loaded from environment variables.
type Config struct {
	Logger     logger.Config
	PostgreSQL postgresql.Config
	Scanner    scanner.Config
	Workers    app.ScannerWorkersConfig
	CVESeed    cveseed.Config
	Metrics    metricsserver.Config
}

func parseConfig(config *Config) error {
	if err := envsecret.LoadFromFiles(map[string]string{
		"POSTGRES_PASSWORD": "POSTGRES_PASSWORD_FILE",
	}); err != nil {
		return fmt.Errorf("can't load file-backed secrets: %w", err)
	}

	if err := cleanenv.ReadEnv(config); err != nil {
		return fmt.Errorf("can't parse config: %w", err)
	}

	return nil
}

func main() {
	banner.Print("uv-scanner", "Network Scanner")

	var config Config

	if err := parseConfig(&config); err != nil {
		log.Fatal(err)
	}

	zlog, err := logger.NewLogger(&config.Logger)
	if err != nil {
		log.Fatal(err)
	}

	defer func() { _ = zlog.Sync() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := run(ctx, &config, zlog); err != nil && !errors.Is(err, context.Canceled) {
		zlog.Fatalw("Scanner exited with error", zap.Error(err))
	}
}

// run constructs the scanner application and dispatches to the selected
// sub-command (worker or one-shot scan).
func run(ctx context.Context, config *Config, zlog *zap.SugaredLogger) error {
	pool, err := postgresql.NewPostgreSQL(ctx, &config.PostgreSQL)
	if err != nil {
		return fmt.Errorf("can't create PostgreSQL connection: %w", err)
	}

	defer pool.Close()

	go poolmetrics.Run(ctx, pool, "uv-scanner", zlog)

	if migrateErr := postgresql.Migrate(ctx, &config.PostgreSQL); migrateErr != nil {
		return fmt.Errorf("can't migrate PostgreSQL schema: %w", migrateErr)
	}

	if repairErr := cveseed.TryRepairCVECatalogSyncState(ctx, pool, zlog); repairErr != nil {
		return fmt.Errorf("can't repair CVE catalog sync state: %w", repairErr)
	}

	if seedErr := cveseed.MaybeRestore(ctx, pool, &config.PostgreSQL, config.CVESeed.SeedFile, config.CVESeed.SeedDir, zlog); seedErr != nil {
		return fmt.Errorf("can't restore CVE catalog from seed: %w", seedErr)
	}

	repos := app.NewRepositories(pool)

	app.BootstrapCPEMap(ctx, repos.CPEProductMap, zlog)

	riskPolicyService := riskpolicysvc.New(riskpolicysvc.DefaultConfig(), repos.RiskPolicy, zlog)
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
		hostsvc.Config{HighRiskThreshold: config.Workers.HostRisk.Threshold},
		pool,
		repos.Host,
		repos.Service,
		repos.RiskSnapshot,
		repos.AttackPath,
		riskPolicyService,
		riskSignalsCollector,
		serviceScoringService,
		remediationEngine,
		zlog,
	)

	recomputeQueue := hostsvc.NewRecomputeQueue(config.Workers.RecomputeQueue, hostRiskService, zlog)

	cveMatcher := cvesvc.NewMatcher(
		config.Workers.CVEMatcher,
		pool,
		repos.ServiceFingerprint,
		repos.CVECatalog,
		repos.CVEMatch,
		repos.CVEMatchState,
		repos.Service,
		recomputeQueue,
	)

	ingestor := ingest.New(pool, repos.IngestRepositories())

	pipeline, err := scanner.NewPipeline(config.Scanner, ingestor, repos.Host, repos.DNS, zlog)
	if err != nil {
		return fmt.Errorf("can't create scanner pipeline: %w", err)
	}

	pipeline.WithCVEMatcher(cveMatcher)
	pipeline.WithHostRiskAggregator(hostRiskService)

	defer pipeline.Close()

	command := commandWorker
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	switch command {
	case commandScan:
		return runOneShotScan(ctx, pipeline, os.Args[2:], zlog)
	case commandWorker:
		return runWorker(ctx, config, pool, repos, pipeline, cveMatcher, hostRiskService, recomputeQueue, zlog)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func runWorker(
	ctx context.Context,
	config *Config,
	pool *pgxpool.Pool,
	repos *app.Repositories,
	pipeline *scanner.Pipeline,
	cveMatcher *cvesvc.Matcher,
	hostRiskService *hostsvc.RiskService,
	recomputeQueue *hostsvc.RecomputeQueue,
	zlog *zap.SugaredLogger,
) error {
	zlog.Info("Start scanner worker")

	if reclaimed, err := repos.Scan.ReclaimAllRunning(ctx); err != nil {
		zlog.Warnw("Can't reclaim running scans on startup", zap.Error(err))
	} else if reclaimed > 0 {
		zlog.Warnw("Reclaimed running scans left over from previous worker run", zap.Uint64("count", reclaimed))
	}

	go sampleQueueDepth(ctx, repos, zlog)

	metrics := metricsserver.NewServer(&config.Metrics, zlog)

	cancelListener := cancel.NewListener(pool, repos.Scan, zlog)
	pauseListener := pause.NewListener(pool, repos.Scan, zlog)

	jobs := app.NewScannerWorkers(config.Workers, pool, repos, pipeline, cveMatcher, hostRiskService, cancelListener, pauseListener, zlog)

	hotRunner := worker.NewRunner(config.Workers.Worker.PollInterval, zlog, jobs.Hot...)
	backgroundRunner := worker.NewRunner(config.Workers.Worker.BackgroundPollInterval, zlog, jobs.Background...)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return metrics.Run(ctx) })
	g.Go(func() error { return cancelListener.Run(ctx) })
	g.Go(func() error { return pauseListener.Run(ctx) })
	g.Go(func() error { return recomputeQueue.Run(ctx) })
	g.Go(func() error { return hotRunner.Run(ctx) })
	g.Go(func() error { return backgroundRunner.Run(ctx) })

	return g.Wait()
}

func runOneShotScan(
	ctx context.Context,
	pipeline *scanner.Pipeline,
	args []string,
	zlog *zap.SugaredLogger,
) error {
	flags := flag.NewFlagSet(commandScan, flag.ContinueOnError)
	cidr := flags.String("cidr", "", "CIDR to scan")
	portsRaw := flags.String("ports", "80,443", "comma-separated TCP ports")
	modeRaw := flags.String(
		"mode",
		"slow",
		"port discovery: slow (TCP connect), masscan (SYN, IPv4 only), or zmap (SYN, IPv4 only)",
	)

	if err := flags.Parse(args); err != nil {
		return err
	}

	if *cidr == "" {
		return errors.New("CIDR is required")
	}

	mode, err := scanmode.Parse(*modeRaw)
	if err != nil {
		return err
	}

	ports, err := parsePorts(*portsRaw)
	if err != nil {
		return err
	}

	zlog.Infow("Start one-shot scan",
		zap.String("cidr", *cidr),
		zap.Int("ports_count", len(ports)),
		zap.String("mode", mode.String()),
	)

	stats, err := pipeline.Run(ctx, scanner.Request{
		CIDR:  *cidr,
		Ports: ports,
		Mode:  mode,
		Progress: func(_ context.Context, stats scanner.Stats) error {
			zlog.Infow("Scan progress", zap.Any("stats", stats.Map()))

			return nil
		},
	})
	if err != nil {
		return err
	}

	zlog.Infow("Scan done", zap.Any("stats", stats.Map()))

	return nil
}

// queueDepthSampleInterval is how often the scanner publishes pending/running/paused counts.
const queueDepthSampleInterval = 30 * time.Second

func sampleQueueDepth(ctx context.Context, repos *app.Repositories, zlog *zap.SugaredLogger) {
	publish := func() {
		statuses := []scanrepository.Status{
			scanrepository.StatusPending,
			scanrepository.StatusRunning,
			scanrepository.StatusPaused,
		}

		for _, status := range statuses {
			count, err := repos.Scan.CountByStatus(ctx, status)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}

				zlog.Debugw("Can't sample scan queue depth", zap.String("status", string(status)), zap.Error(err))

				continue
			}

			scanmetrics.QueueDepth.WithLabelValues(string(status)).Set(float64(count))
		}
	}

	publish()

	ticker := time.NewTicker(queueDepthSampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publish()
		}
	}
}

func parsePorts(raw string) ([]uint16, error) {
	if raw == "" {
		return nil, errors.New("ports are required")
	}

	parts := strings.Split(raw, ",")
	ports := make([]uint16, 0, len(parts))

	for _, part := range parts {
		value, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("can't parse port %q: %w", part, err)
		}

		if value == 0 {
			return nil, fmt.Errorf("can't parse port %q: must be in range 1..65535", part)
		}

		ports = append(ports, uint16(value))
	}

	return ports, nil
}
