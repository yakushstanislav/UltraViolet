package handler

import (
	"net/http"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
)

func (h *Router) meHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.sendJSONResponse(w, http.StatusOK, map[string]any{
		"role":    string(auth.RoleFromContext(ctx)),
		"user_id": auth.UserIDFromContext(ctx),
	})
}

func (h *Router) registerMeAPI(api *apiRouter) {
	h.registerProtectedRoutes(api, []protectedRoute{
		{
			http.MethodGet,
			"/me",
			[]auth.Role{auth.RoleViewer, auth.RoleOperator},
			h.meHandler,
		},
	})
}
