package handler

import (
	"net/http"

	scandto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/scan"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

func (h *Router) createScanScheduleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req scandto.CreateScheduleRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	schedule, err := h.services.ScanSchedule.Create(ctx, &req)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusCreated, schedule)
}

func (h *Router) listScanSchedulesHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	response, err := h.services.ScanSchedule.List(ctx, page, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) getScanScheduleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	schedule, err := h.services.ScanSchedule.GetByID(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, schedule)
}

func (h *Router) updateScanScheduleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req scandto.UpdateScheduleRequest
	if err = h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err = req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	schedule, err := h.services.ScanSchedule.Update(ctx, id, &req)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, schedule)
}

func (h *Router) setScanScheduleEnabledHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req scandto.SetScheduleEnabledRequest
	if err = h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err = req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	schedule, err := h.services.ScanSchedule.SetEnabled(ctx, id, req.Enabled)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, schedule)
}

func (h *Router) runScanScheduleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	schedule, err := h.services.ScanSchedule.RunNow(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, schedule)
}

func (h *Router) deleteScanScheduleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	if err := h.services.ScanSchedule.Delete(ctx, id); err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Router) registerScanScheduleAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}
	write := []auth.Role{auth.RoleOperator}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodPost, "/scan-schedules", write, h.withDemoGuard(h.createScanScheduleHandler)},
		{http.MethodGet, "/scan-schedules", read, h.listScanSchedulesHandler},
		{http.MethodGet, "/scan-schedules/{id}", read, h.getScanScheduleHandler},
		{http.MethodPatch, "/scan-schedules/{id}", write, h.withDemoGuard(h.updateScanScheduleHandler)},
		{http.MethodPatch, "/scan-schedules/{id}/enabled", write, h.withDemoGuard(h.setScanScheduleEnabledHandler)},
		{http.MethodPost, "/scan-schedules/{id}/run", write, h.withDemoGuard(h.runScanScheduleHandler)},
		{http.MethodDelete, "/scan-schedules/{id}", write, h.withDemoGuard(h.deleteScanScheduleHandler)},
	})
}
