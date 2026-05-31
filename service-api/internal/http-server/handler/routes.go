package handler

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
)

// protectedRoute binds one versioned API endpoint to an RBAC role set.
type protectedRoute struct {
	method  string
	path    string
	roles   []auth.Role
	handler http.HandlerFunc
}

// registerProtectedRoutes dispatches each route to the matching apiRouter
// helper. Method dispatch goes through a lookup table so unsupported verbs
// fail at startup with a logged error rather than panicking later.
func (h *Router) registerProtectedRoutes(api *apiRouter, routes []protectedRoute) {
	registrars := map[string]func(string, http.HandlerFunc){
		http.MethodGet:    api.Get,
		http.MethodPost:   api.Post,
		http.MethodDelete: api.Delete,
		http.MethodPatch:  api.Patch,
	}

	for _, route := range routes {
		register, ok := registrars[route.method]
		if !ok {
			h.logger.Fatalw("Unsupported HTTP method for protected route",
				zap.String("method", route.method),
				zap.String("path", route.path),
			)
		}

		register(route.path, h.withRoles(route.handler, route.roles...))
	}
}
