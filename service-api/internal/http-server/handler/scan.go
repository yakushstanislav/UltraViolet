package handler

import (
	"net/http"
	"strings"

	"go.uber.org/zap"

	scandto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/scan"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	scanrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
)

func (h *Router) createScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req scandto.CreateRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	req.ApplyDefaults()

	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	response, err := h.services.Scan.Create(ctx, &req)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusCreated, response)
}

func (h *Router) getScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	scanJob, err := h.services.Scan.GetByID(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, scanJob)
}

func (h *Router) cancelScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	response, err := h.services.Scan.RequestCancel(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	requestLogger.Infow("Scan cancel requested",
		zap.Uint64("id", id),
		zap.String("status", response.Status),
	)

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) pauseScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	response, err := h.services.Scan.RequestPause(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	requestLogger.Infow("Scan pause requested",
		zap.Uint64("id", id),
		zap.String("status", response.Status),
	)

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) resumeScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	response, err := h.services.Scan.RequestResume(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	requestLogger.Infow("Scan resume requested",
		zap.Uint64("id", id),
		zap.String("status", response.Status),
	)

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) restartScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	response, err := h.services.Scan.Restart(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	requestLogger.Infow("Scan restart requested",
		zap.Uint64("id", response.ID),
		zap.String("status", response.Status),
	)

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) getAllScansHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	sortColumn, sortDesc := parseScanListSortQuery(r)

	response, err := h.services.Scan.GetAll(ctx, page, limit, offset, sortColumn, sortDesc)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func parseScanListSortQuery(r *http.Request) (sortColumn string, sortDesc bool) {
	sortColumn = "id"
	sortDesc = true

	rawSort := strings.ToLower(r.URL.Query().Get("sort"))
	if scanrepository.IsValidSortColumn(rawSort) {
		sortColumn = rawSort
	}

	rawOrder := strings.ToLower(r.URL.Query().Get("order"))
	if rawOrder == "asc" {
		sortDesc = false
	}

	return sortColumn, sortDesc
}

func (h *Router) registerScanAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}
	write := []auth.Role{auth.RoleOperator}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodPost, "/scans", write, h.withDemoGuard(h.createScanHandler)},
		{http.MethodGet, "/scans", read, h.getAllScansHandler},
		{http.MethodGet, "/scans/{id}", read, h.getScanHandler},
		{http.MethodPost, "/scans/{id}/cancel", write, h.withDemoGuard(h.cancelScanHandler)},
		{http.MethodPost, "/scans/{id}/pause", write, h.withDemoGuard(h.pauseScanHandler)},
		{http.MethodPost, "/scans/{id}/resume", write, h.withDemoGuard(h.resumeScanHandler)},
		{http.MethodPost, "/scans/{id}/restart", write, h.withDemoGuard(h.restartScanHandler)},
	})
}
