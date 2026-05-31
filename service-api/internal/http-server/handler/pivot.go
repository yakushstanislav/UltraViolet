package handler

import (
	"net/http"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/dto/pivot"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

const pivotDefaultLimit uint64 = 200

func (h *Router) pivotHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	kind := r.PathValue("kind")
	value := r.PathValue("value")

	limit, err := parseUint64FromQuery(r, "limit", pivotDefaultLimit)
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	req := pivot.Request{Kind: kind, Value: value, Limit: limit}
	if err = req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	resp, err := h.services.Pivot.Find(ctx, req.Kind, req.Value, req.Limit)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, resp)
}

func (h *Router) registerPivotAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodGet, "/pivot/{kind}/{value}", read, h.pivotHandler},
	})
}
