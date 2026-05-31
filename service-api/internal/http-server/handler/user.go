package handler

import (
	"net/http"

	userdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/user"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	userservice "github.com/yakushstanislav/UltraViolet/service-api/internal/services/user"
)

func (h *Router) listUsersHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	q := r.URL.Query().Get("q")

	role := r.URL.Query().Get("role")
	if role != "" && role != string(auth.RoleViewer) && role != string(auth.RoleOperator) && role != string(auth.RoleAdmin) {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	response, err := h.services.User.List(ctx, page, limit, offset, q, role)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) createUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	var req userdto.CreateUserRequest
	if err := h.decodeBody(w, r, &req); err != nil {
		h.writeDecodeError(w, err)

		return
	}

	if err := req.IsValid(); err != nil {
		httperror.WriteInvalidArgument(w, requestLogger, userservice.ValidationAPIReason(err))

		return
	}

	user, err := h.services.User.Create(ctx, &req)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusCreated, user)
}

func (h *Router) getUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	user, err := h.services.User.GetByID(ctx, id)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, user)
}

func (h *Router) changeUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req userdto.ChangeRoleRequest
	if decodeErr := h.decodeBody(w, r, &req); decodeErr != nil {
		h.writeDecodeError(w, decodeErr)

		return
	}

	if validErr := req.IsValid(); validErr != nil {
		httperror.WriteInvalidArgument(w, requestLogger, userservice.ValidationAPIReason(validErr))

		return
	}

	user, err := h.services.User.ChangeRole(ctx, id, req.Role)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, user)
}

func (h *Router) resetUserPasswordHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req userdto.ResetPasswordRequest
	if decodeErr := h.decodeBody(w, r, &req); decodeErr != nil {
		h.writeDecodeError(w, decodeErr)

		return
	}

	if validErr := req.IsValid(); validErr != nil {
		httperror.WriteInvalidArgument(w, requestLogger, userservice.ValidationAPIReason(validErr))

		return
	}

	if err := h.services.User.ResetPassword(ctx, id, req.Password); err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Router) setUserActiveHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req userdto.SetActiveRequest
	if decodeErr := h.decodeBody(w, r, &req); decodeErr != nil {
		h.writeDecodeError(w, decodeErr)

		return
	}

	if validErr := req.IsValid(); validErr != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeInvalidArgument)

		return
	}

	user, err := h.services.User.SetActive(ctx, id, req.Active)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, user)
}

func (h *Router) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	if err := h.services.User.Delete(ctx, id); err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Router) registerUserAPI(api *apiRouter) {
	admin := []auth.Role{auth.RoleAdmin}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodGet, "/users", admin, h.listUsersHandler},
		{http.MethodPost, "/users", admin, h.withDemoGuard(h.createUserHandler)},
		{http.MethodGet, "/users/{id}", admin, h.getUserHandler},
		{http.MethodPatch, "/users/{id}/role", admin, h.changeUserRoleHandler},
		{http.MethodPatch, "/users/{id}/password", admin, h.withDemoGuard(h.resetUserPasswordHandler)},
		{http.MethodPatch, "/users/{id}/active", admin, h.setUserActiveHandler},
		{http.MethodDelete, "/users/{id}", admin, h.withDemoGuard(h.deleteUserHandler)},
	})
}
