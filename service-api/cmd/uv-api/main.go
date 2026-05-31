package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/app"
	httpserver "github.com/yakushstanislav/UltraViolet/service-api/internal/http-server"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler"
	metricsserver "github.com/yakushstanislav/UltraViolet/service-api/internal/metrics-server"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/banner"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cveseed"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/envsecret"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/events"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/geoip"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/poolmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/postgresql"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanpolicy"
	realtimeserver "github.com/yakushstanislav/UltraViolet/service-api/internal/realtime-server"
	cvesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/cve"
	usersvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/user"
)

const shutdownTimeout = 15 * time.Second

// Config is the root application configuration loaded from the environment.
type Config struct {
	Logger     logger.Config
	Server     httpserver.Config
	Metrics    metricsserver.Config
	Realtime   realtimeserver.Config
	Handler    handler.Config
	ScanPolicy scanpolicy.Config
	GeoIP      geoip.Config
	PostgreSQL postgresql.Config
	Bootstrap  BootstrapConfig
	CVE        cvesvc.Config
	CVESeed    cveseed.Config
}

// BootstrapConfig seeds the first administrative user when the database is empty.
type BootstrapConfig struct {
	Username string `env:"AUTH_BOOTSTRAP_USERNAME"`
	Password string `env:"AUTH_BOOTSTRAP_PASSWORD"`
	Role     string `env:"AUTH_BOOTSTRAP_ROLE"`
}

func parseConfig(config *Config) error {
	if err := envsecret.LoadFromFiles(map[string]string{
		"POSTGRES_PASSWORD": "POSTGRES_PASSWORD_FILE",
		"AUTH_JWT_SECRET":   "AUTH_JWT_SECRET_FILE",
	}); err != nil {
		return fmt.Errorf("can't load file-backed secrets: %w", err)
	}

	if err := cleanenv.ReadEnv(config); err != nil {
		return fmt.Errorf("can't parse config: %w", err)
	}

	return nil
}

func main() {
	banner.Print("uv-api", "HTTP API")

	var config Config

	if err := parseConfig(&config); err != nil {
		log.Fatal(err)
	}

	if err := config.Handler.Auth.Validate(); err != nil {
		log.Fatal(err)
	}

	zlog, err := logger.NewLogger(&config.Logger)
	if err != nil {
		log.Fatal(err)
	}

	defer func() { _ = zlog.Sync() }()

	zlog.Info("API server starting")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	db, err := postgresql.NewPostgreSQL(ctx, &config.PostgreSQL)
	if err != nil {
		zlog.Fatalw("Can't create PostgreSQL connection", zap.Error(err))
	}

	defer db.Close()

	go poolmetrics.Run(ctx, db, "uv-api", zlog)

	if err := postgresql.Migrate(ctx, &config.PostgreSQL); err != nil {
		zlog.Fatalw("Can't migrate PostgreSQL schema", zap.Error(err))
	}

	if err := cveseed.TryRepairCVECatalogSyncState(ctx, db, zlog); err != nil {
		zlog.Fatalw("Can't repair CVE catalog sync state", zap.Error(err))
	}

	if err := cveseed.MaybeRestore(ctx, db, &config.PostgreSQL, config.CVESeed.SeedFile, config.CVESeed.SeedDir, zlog); err != nil {
		zlog.Fatalw("Can't restore CVE catalog from seed", zap.Error(err))
	}

	repos := app.NewRepositories(db)

	if err := usersvc.NewService(repos.User, repos.RefreshToken, zlog).EnsureBootstrap(ctx, usersvc.BootstrapConfig{
		Username: config.Bootstrap.Username,
		Password: config.Bootstrap.Password,
		Role:     config.Bootstrap.Role,
	}); err != nil {
		zlog.Fatalw("Can't bootstrap auth user", zap.Error(err))
	}

	services := app.NewServices(db, repos, app.ServicesConfig{
		Auth:       config.Handler.Auth,
		ScanPolicy: config.ScanPolicy,
		GeoIP:      config.GeoIP,
		CVE:        config.CVE,
		ONVIF:      config.Handler.ONVIF,
		RTSP:       config.Handler.RTSP,
	}, zlog)

	eventsBus := events.NewBus()
	eventsListener := events.NewListener(db, repos.Scan, eventsBus, zlog)

	httpHandler := handler.New(&config.Handler, services, zlog)
	apiServer := httpserver.NewServer(&config.Server, zlog)
	metrics := metricsserver.NewServer(&config.Metrics, zlog)
	realtime := realtimeserver.NewServer(
		&config.Realtime,
		config.Handler.Auth,
		config.Handler.CORS,
		eventsBus,
		zlog,
	)

	if err := run(ctx, zlog, apiServer, metrics, realtime, eventsListener, httpHandler); err != nil &&
		!errors.Is(err, context.Canceled) {
		zlog.Fatalw("Server exited with error", zap.Error(err))
	}
}

// run starts both servers in an errgroup and shuts them down on the first
// terminating signal or server error.
func run(
	ctx context.Context,
	zlog *zap.SugaredLogger,
	apiServer *httpserver.Server,
	metrics *metricsserver.Server,
	realtime *realtimeserver.Server,
	eventsListener *events.Listener,
	httpHandler *handler.Router,
) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return apiServer.Run(ctx, httpHandler)
	})

	g.Go(func() error {
		return metrics.Run(ctx)
	})

	g.Go(func() error {
		return realtime.Run(ctx)
	})

	g.Go(func() error {
		return eventsListener.Run(ctx)
	})

	g.Go(func() error {
		<-ctx.Done()

		zlog.Info("API server stopping")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := metrics.Shutdown(shutdownCtx); err != nil {
			zlog.Errorw("Can't stop metrics server", zap.Error(err))
		}

		if err := realtime.Shutdown(shutdownCtx); err != nil {
			zlog.Errorw("Can't stop realtime server", zap.Error(err))
		}

		if err := apiServer.Shutdown(shutdownCtx); err != nil {
			zlog.Errorw("Can't stop HTTP server", zap.Error(err))
		}

		return nil
	})

	return g.Wait()
}
