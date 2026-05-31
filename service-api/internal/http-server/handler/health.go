package handler

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/buildinfo"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

func (h *Router) healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	requestLogger := logger.UnpackContext(ctx)

	if err := h.services.Host.Ping(ctx); err != nil {
		requestLogger.Errorw("Health check failed", zap.Error(err))

		httperror.WriteCode(w, requestLogger, http.StatusServiceUnavailable, "database_unreachable")

		return
	}

	h.sendJSONResponse(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": buildinfo.Version,
		"commit":  buildinfo.Commit,
	})
}
