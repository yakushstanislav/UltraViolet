package handler

import (
	"net/http"
	"net/netip"
	"time"

	deltadto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/delta"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	deltarepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/delta"
)

func (h *Router) getScanDeltaHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	summary, err := h.services.Delta.GetSummary(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	resp := &deltadto.SummaryResponse{
		ScanID:              summary.ScanID,
		NewServices:         summary.NewServices,
		DisappearedServices: summary.DisappearedServices,
		ChangedServices:     summary.ChangedServices,
		CreatedAt:           summary.CreatedAt.UTC().Format(time.RFC3339),
	}

	if summary.PreviousScanID.Valid {
		v := uint64(summary.PreviousScanID.Int64)

		resp.PreviousScanID = &v
	}

	h.sendJSONResponse(w, http.StatusOK, resp)
}

func (h *Router) getHostTimelineHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	items, total, err := h.services.Delta.GetHostTimeline(ctx, addr, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, NewPageResponse[*deltarepository.ChangeEvent](page, limit, total, items))
}

func (h *Router) getScanDeltaEventsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	items, total, err := h.services.Delta.GetScanEvents(ctx, id, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, NewPageResponse[*deltarepository.ChangeEvent](page, limit, total, items))
}

func (h *Router) registerDeltaAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodGet, "/scans/{id}/delta", read, h.getScanDeltaHandler},
		{http.MethodGet, "/scans/{id}/delta/events", read, h.getScanDeltaEventsHandler},
		{http.MethodGet, "/hosts/{ip}/timeline", read, h.getHostTimelineHandler},
	})
}
