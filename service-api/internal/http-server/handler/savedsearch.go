package handler

import (
	"net/http"

	"go.uber.org/zap"

	featuredto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/feature"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

func (h *Router) createSavedSearchHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req featuredto.CreateSavedSearchRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	id, err := h.services.SavedSearch.Create(ctx, req.Name, req.Query)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *Router) listSavedSearchesHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	items, total, err := h.services.SavedSearch.GetAll(ctx, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	out := make([]*featuredto.SavedSearchResponse, 0, len(items))

	for _, item := range items {
		out = append(out, featuredto.NewSavedSearchResponse(item))
	}

	h.sendJSONResponse(w, http.StatusOK, NewPageResponse[*featuredto.SavedSearchResponse](page, limit, total, out))
}

func (h *Router) deleteSavedSearchHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	if err := h.services.SavedSearch.Delete(ctx, id); err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Router) runSavedSearchHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	item, err := h.services.SavedSearch.Get(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	if err := h.services.SavedSearch.MarkRun(ctx, id); err != nil {
		requestLogger.Warnw("Can't mark saved search as run", zap.Error(err))
	}

	h.sendJSONResponse(w, http.StatusOK, map[string]any{
		"id":    item.ID,
		"name":  item.Name,
		"query": item.Query,
	})
}

func (h *Router) registerSavedSearchAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodPost, "/saved-searches", []auth.Role{auth.RoleOperator}, h.withDemoGuard(h.createSavedSearchHandler)},
		{http.MethodGet, "/saved-searches", read, h.listSavedSearchesHandler},
		{http.MethodDelete, "/saved-searches/{id}", []auth.Role{auth.RoleOperator}, h.withDemoGuard(h.deleteSavedSearchHandler)},
		{http.MethodPost, "/saved-searches/{id}/run", read, h.runSavedSearchHandler},
	})
}
