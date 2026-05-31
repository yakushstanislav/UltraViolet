package metricsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Config holds the metrics server settings.
type Config struct {
	Addr string `env:"METRICS_ADDR" env-required:"true"`
	Port int    `env:"METRICS_PORT" env-required:"true"`
}

// Server exposes the Prometheus /metrics endpoint.
type Server struct {
	config *Config
	server *http.Server
	mu     sync.Mutex
	logger *zap.SugaredLogger
}

// NewServer builds a new metrics server.
func NewServer(config *Config, logger *zap.SugaredLogger) *Server {
	return &Server{
		config: config,
		logger: logger,
	}
}

// Run binds the listener and serves the metrics endpoint until ctx is
// canceled or Serve fails.
func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Addr, s.config.Port)

	listen, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("can't bind metrics listener: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
	}

	s.mu.Lock()
	s.server = server
	s.mu.Unlock()

	s.logger.Infow("Metrics server listening", zap.String("addr", addr))

	if err := server.Serve(listen); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("can't serve metrics server: %w", err)
	}

	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	server := s.server
	s.mu.Unlock()

	if server == nil {
		return nil
	}

	s.logger.Info("Stopping metrics server")

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("can't shutdown metrics server: %w", err)
	}

	return nil
}
