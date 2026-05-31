package realtimeserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/cors"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/events"
)

// Config holds the dedicated WebSocket listener settings.
type Config struct {
	Addr         string `env:"REALTIME_ADDR" env-required:"true"`
	Port         int    `env:"REALTIME_PORT" env-required:"true"`
	AllowedRoles string `env:"REALTIME_WS_ALLOWED_ROLES" env-default:"viewer,operator,admin"`
}

// Server serves long-lived WebSocket connections on a separate HTTP listener.
type Server struct {
	config    *Config
	auth      auth.Config
	cors      cors.Config
	eventsBus events.Bus
	server    *http.Server
	mu        sync.Mutex
	logger    *zap.SugaredLogger
}

// NewServer builds a realtime server that shares the in-process events bus with uv-api.
func NewServer(
	config *Config,
	authConfig auth.Config,
	corsConfig cors.Config,
	eventsBus events.Bus,
	logger *zap.SugaredLogger,
) *Server {
	return &Server{
		config:    config,
		auth:      authConfig,
		cors:      corsConfig,
		eventsBus: eventsBus,
		logger:    logger,
	}
}

// Run binds the listener and serves until ctx is canceled or Serve fails.
func (s *Server) Run(ctx context.Context) error {
	addr := formatAddr(s.config.Addr, s.config.Port)

	listen, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("can't bind realtime listener: %w", err)
	}

	mux := http.NewServeMux()
	wsHandler := newWSHandler(s.auth, s.cors, parseWSAllowedRoles(s.config.AllowedRoles), s.eventsBus, s.logger)
	mux.HandleFunc("GET /v1/ws", wsHandler.serve)

	handler := cors.Middleware(&s.cors, mux)

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	s.mu.Lock()
	s.server = server
	s.mu.Unlock()

	s.logger.Infow("Realtime server listening", zap.String("addr", addr))

	if err := server.Serve(listen); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("can't serve realtime server: %w", err)
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

	s.logger.Info("Stopping realtime server")

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("can't shutdown realtime server: %w", err)
	}

	return nil
}

func formatAddr(addr string, port int) string {
	return fmt.Sprintf("%s:%d", addr, port)
}
