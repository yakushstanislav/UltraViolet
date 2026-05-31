package handler

import (
	"net/http"

	featuredto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/feature"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	alertrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/alert"
)

func (h *Router) createAlertHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req featuredto.CreateAlertRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	query := req.Query
	if query == nil {
		query = map[string]any{}
	}

	if req.Q != "" {
		query["q"] = req.Q
	}

	channel := req.Channel
	if channel == "" {
		channel = "log"
	}

	cooldown := req.CooldownSec
	if cooldown <= 0 {
		cooldown = 300
	}

	id, err := h.services.Alert.CreateRule(ctx, &alertrepository.Rule{
		Name:        req.Name,
		Query:       query,
		Channel:     channel,
		Destination: req.Destination,
		CooldownSec: cooldown,
		Enabled:     true,
	})
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *Router) listAlertsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	items, total, err := h.services.Alert.GetRules(ctx, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	out := make([]*featuredto.AlertRuleResponse, 0, len(items))
	for _, item := range items {
		out = append(out, featuredto.NewAlertRuleResponse(item))
	}

	h.sendJSONResponse(w, http.StatusOK, NewPageResponse[*featuredto.AlertRuleResponse](page, limit, total, out))
}

func (h *Router) listAlertsAllHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	items, total, err := h.services.Alert.GetAllRules(ctx, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	out := make([]*featuredto.AlertRuleResponse, 0, len(items))
	for _, item := range items {
		out = append(out, featuredto.NewAlertRuleResponse(item))
	}

	h.sendJSONResponse(w, http.StatusOK, NewPageResponse[*featuredto.AlertRuleResponse](page, limit, total, out))
}

func (h *Router) deleteAlertHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	if err := h.services.Alert.DeleteRule(ctx, id); err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Router) setAlertEnabledHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req featuredto.SetAlertEnabledRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	if err := h.services.Alert.SetRuleEnabled(ctx, id, req.Enabled); err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Router) listAlertEventsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	items, total, err := h.services.Alert.GetEvents(ctx, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	out := make([]*featuredto.AlertEventResponse, 0, len(items))
	for _, item := range items {
		out = append(out, featuredto.NewAlertEventResponse(item))
	}

	h.sendJSONResponse(w, http.StatusOK, NewPageResponse[*featuredto.AlertEventResponse](page, limit, total, out))
}

func (h *Router) registerAlertAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodPost, "/alerts", []auth.Role{auth.RoleOperator}, h.withDemoGuard(h.createAlertHandler)},
		{http.MethodGet, "/alerts", read, h.listAlertsHandler},
		{http.MethodGet, "/alerts/all", read, h.listAlertsAllHandler},
		{http.MethodDelete, "/alerts/{id}", []auth.Role{auth.RoleOperator}, h.withDemoGuard(h.deleteAlertHandler)},
		{http.MethodPatch, "/alerts/{id}/enabled", []auth.Role{auth.RoleOperator}, h.withDemoGuard(h.setAlertEnabledHandler)},
		{http.MethodGet, "/alerts/events", read, h.listAlertEventsHandler},
	})
}
