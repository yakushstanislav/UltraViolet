package handler

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

// getHostHTTPScreenshotHandler serves the rendered JPEG thumbnail for one HTTP
// service. The path keeps the host scope explicit so a stray service id from
// another host can never resolve.
func (h *Router) getHostHTTPScreenshotHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	serviceID, err := strconv.ParseUint(r.PathValue("service_id"), 10, 64)
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	screenshot, err := h.services.Host.HTTPScreenshot(ctx, addr, serviceID)
	if err != nil {
		if errors.Is(err, pgkit.ErrNoRows) {
			h.sendResponse(w, http.StatusNotFound, httperror.CodeNotFound)

			return
		}

		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "private, max-age=60")

	if screenshot.BodySHA256.Valid && screenshot.BodySHA256.String != "" {
		w.Header().Set("ETag", `"`+screenshot.BodySHA256.String+`"`)
	}

	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(screenshot.Thumbnail); err != nil && h.logger != nil {
		h.logger.Warnw("Can't write HTTP screenshot body", zap.Error(err))
	}
}
