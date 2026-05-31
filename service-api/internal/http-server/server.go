package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler"
)

// Config holds HTTP server settings.
type Config struct {
	Addr string `env:"SERVER_ADDR" env-required:"true"`
	Port int    `env:"SERVER_PORT" env-required:"true"`
}

// Server wraps the http.Server lifecycle.
type Server struct {
	config *Config
	server *http.Server
	mu     sync.Mutex
	logger *zap.SugaredLogger
}

// NewServer builds a new HTTP server.
func NewServer(config *Config, logger *zap.SugaredLogger) *Server {
	return &Server{
		config: config,
		logger: logger,
	}
}

// Run binds the listener and serves until ctx is canceled or Serve fails.
// http.ErrServerClosed (triggered by Shutdown) is treated as a clean stop.
func (s *Server) Run(ctx context.Context, h *handler.Router) error {
	addr := formatAddr(s.config.Addr, s.config.Port)

	listen, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("can't bind HTTP listener: %w", err)
	}

	// ReadTimeout/WriteTimeout must stay zero: they wrap ResponseWriter without
	// http.Hijacker and break WebSocket upgrades; long-lived /v1/ws uses app ping.
	server := &http.Server{
		Addr:              addr,
		Handler:           h.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	s.mu.Lock()
	s.server = server
	s.mu.Unlock()

	s.logger.Infow("HTTP server listening", zap.String("addr", addr))

	if err := server.Serve(listen); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("can't serve HTTP server: %w", err)
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

	s.logger.Info("Stopping HTTP server")

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("can't shutdown HTTP server: %w", err)
	}

	return nil
}

func formatAddr(addr string, port int) string {
	return fmt.Sprintf("%s:%d", addr, port)
}
