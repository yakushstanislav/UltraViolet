package handler

import (
	"net/http"

	authdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/auth"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

type authResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Role         string `json:"role"`
}

func (h *Router) loginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req authdto.LoginRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	pair, err := h.services.Auth.Login(ctx, req.Username, req.Password)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, authResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		Role:         pair.Role,
	})
}

func (h *Router) refreshHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req authdto.RefreshRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusUnauthorized, httperror.CodeUnauthorized)

		return
	}

	pair, err := h.services.Auth.Refresh(ctx, req.RefreshToken)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, authResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		Role:         pair.Role,
	})
}

func (h *Router) logoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req authdto.RefreshRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err := req.IsValid(); err != nil {
		h.sendResponse(w, http.StatusUnauthorized, httperror.CodeUnauthorized)

		return
	}

	if err := h.services.Auth.Logout(ctx, req.RefreshToken); err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Router) registerAuthAPI(api *apiRouter) {
	api.Post("/auth/login", h.throttleAuth(h.loginHandler))
	api.Post("/auth/refresh", h.throttleAuth(h.refreshHandler))
	api.Post("/auth/logout", h.withRoles(h.logoutHandler, auth.RoleViewer, auth.RoleOperator))
}

func (h *Router) throttleAuth(next http.HandlerFunc) http.HandlerFunc {
	wrapped := h.authThrottle(next)

	return func(w http.ResponseWriter, r *http.Request) {
		wrapped.ServeHTTP(w, r)
	}
}
