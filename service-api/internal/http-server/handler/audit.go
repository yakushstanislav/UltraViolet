package handler

import (
	"net/http"
	"strconv"
	"time"

	auditdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/audit"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

func (h *Router) listAuditEventsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	params, err := h.parseAuditListParams(w, r)
	if err != nil {
		return
	}

	if validationErr := params.IsValid(); validationErr != nil {
		httperror.WriteCode(w, requestLogger, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	items, total, err := h.services.Audit.List(ctx, params.ToRepositoryFilter(), limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	out := make([]*auditdto.Event, 0, len(items))
	for _, item := range items {
		out = append(out, auditdto.NewEventResponse(item))
	}

	h.sendJSONResponse(w, http.StatusOK, NewPageResponse[*auditdto.Event](page, limit, total, out))
}

func (h *Router) parseAuditListParams(w http.ResponseWriter, r *http.Request) (*auditdto.ListParams, error) {
	q := r.URL.Query()

	params := &auditdto.ListParams{
		Method:       q.Get("method"),
		StatusFamily: q.Get("status_family"),
		Query:        q.Get("q"),
	}

	if raw := q.Get("user_id"); raw != "" {
		userID, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			httperror.WriteCode(w, logger.UnpackContext(r.Context()), http.StatusBadRequest, httperror.CodeParseURL)

			return nil, errInvalidArgument
		}

		params.UserID = &userID
	}

	if raw := q.Get("since"); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			httperror.WriteCode(w, logger.UnpackContext(r.Context()), http.StatusBadRequest, httperror.CodeParseURL)

			return nil, errInvalidArgument
		}

		params.Since = &since
	}

	if raw := q.Get("until"); raw != "" {
		until, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			httperror.WriteCode(w, logger.UnpackContext(r.Context()), http.StatusBadRequest, httperror.CodeParseURL)

			return nil, errInvalidArgument
		}

		params.Until = &until
	}

	return params, nil
}

func (h *Router) registerAuditAPI(api *apiRouter) {
	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodGet, "/audit", []auth.Role{auth.RoleAdmin}, h.listAuditEventsHandler},
	})
}
