package handler

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

const (
	relatedHostsDefaultLimit uint64 = 10
)

func (h *Router) getHostHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	hostDTO, err := h.services.Host.GetByIP(ctx, addr, page, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, hostDTO)
}

func (h *Router) getRelatedHostsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	page, err := parseUint64FromQuery(r, "page", 1)
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	limit, err := parseUint64FromQuery(r, "limit", relatedHostsDefaultLimit)
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	req := hostdto.RelatedHostsRequest{Page: page, Limit: limit}
	if err = req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	resp, err := h.services.Host.RelatedByIP(ctx, addr, req.Page, req.Limit)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, resp)
}

func (h *Router) getHostRiskExplainHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	resp, err := h.services.Host.RiskExplain(ctx, addr)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, resp)
}

func (h *Router) getHostRiskHistoryHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	days := parseUintQuery(r, "days", 30, 1, 365)
	limit := parseUintQuery(r, "limit", 1000, 1, 5000)
	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	resp, err := h.services.Host.RiskHistory(ctx, addr, since, limit)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, resp)
}

func parseUintQuery(r *http.Request, key string, fallback, minValue, maxValue uint64) uint64 {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return fallback
	}

	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return fallback
	}

	if v < minValue {
		return minValue
	}

	if v > maxValue {
		return maxValue
	}

	return v
}

func (h *Router) registerHostAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}
	adminOnly := []auth.Role{auth.RoleAdmin}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodGet, "/hosts/{ip}", read, h.getHostHandler},
		{http.MethodGet, "/hosts/{ip}/risk-explain", read, h.getHostRiskExplainHandler},
		{http.MethodGet, "/hosts/{ip}/risk-history", read, h.getHostRiskHistoryHandler},
		{http.MethodGet, "/hosts/{ip}/related", read, h.getRelatedHostsHandler},
		{http.MethodGet, "/hosts/{ip}/services/{service_id}/screenshot", read, h.getHostHTTPScreenshotHandler},
		{http.MethodPost, "/hosts/{ip}/rtsp-snapshot", read, h.postHostRTSPSnapshotHandler},
		{http.MethodPost, "/hosts/{ip}/onvif-command", read, h.postHostONVIFCommandHandler},
		{http.MethodPost, "/hosts/{ip}/onvif-lab-credential-probe", adminOnly, h.postHostONVIFLabCredentialProbeHandler},
		{http.MethodPost, "/hosts/{ip}/onvif-rtsp-snapshot", read, h.postHostONVIFRTSPSnapshotHandler},
	})
}
