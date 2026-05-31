package handler

import (
	"net/http"
	"time"

	dashboarddto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/dashboard"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	trendssvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/dashboard/trends"
)

const (
	defaultTrendsRange = "7d"
	defaultTopLimit    = 10
	maxTopLimit        = 50
)

func (h *Router) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	response, err := h.services.Dashboard.Summary.Compute(ctx, time.Now().UTC())
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) dashboardMapHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	response, err := h.services.Dashboard.Topology.Map(ctx)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) dashboardTrendsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = defaultTrendsRange
	}

	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = trendssvc.DefaultBucketForRange(rng)
	}

	req := &dashboarddto.TrendsRequest{Range: rng, Bucket: bucket}
	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	response, err := h.services.Dashboard.Trends.Compute(ctx, time.Now().UTC(), rng, bucket)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) dashboardTopHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	limit, parseErr := parseUint64FromQuery(r, "limit", defaultTopLimit)
	if parseErr != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	if limit == 0 {
		limit = defaultTopLimit
	}

	if limit > maxTopLimit {
		limit = maxTopLimit
	}

	req := &dashboarddto.TopRequest{Limit: limit}
	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	response, err := h.services.Dashboard.Topology.Top(ctx, limit)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) dashboardRiskHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	response, err := h.services.Dashboard.Risk.Compute(ctx, defaultTopLimit)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) dashboardScansSummaryHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	response, err := h.services.Dashboard.Summary.Scans(ctx, time.Now().UTC())
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) registerDashboardAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodGet, "/dashboard", read, h.dashboardHandler},
		{http.MethodGet, "/dashboard/map", read, h.dashboardMapHandler},
		{http.MethodGet, "/dashboard/trends", read, h.dashboardTrendsHandler},
		{http.MethodGet, "/dashboard/top", read, h.dashboardTopHandler},
		{http.MethodGet, "/dashboard/risk", read, h.dashboardRiskHandler},
		{http.MethodGet, "/dashboard/scans/summary", read, h.dashboardScansSummaryHandler},
	})
}
