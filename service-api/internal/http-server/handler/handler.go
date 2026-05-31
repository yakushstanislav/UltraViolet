package handler

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/app"
	auditmw "github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/audit"
	authmw "github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/cors"
	loggermw "github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/metrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/ratelimit"
	recovermw "github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/recover"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/requestid"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/security"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	onvifsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/onvif"
	rtspsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/rtsp"
)

// apiPrefix is the version prefix shared by every authenticated endpoint.
const apiPrefix = "/v1"

// apiRouter is a thin wrapper over *http.ServeMux that prepends apiPrefix and
// formats the method+path pattern, so registration sites stay declarative.
type apiRouter struct {
	mux *http.ServeMux
}

func newAPIRouter(mux *http.ServeMux) *apiRouter {
	return &apiRouter{mux: mux}
}

// Get registers handler for "GET /v1<path>".
func (r *apiRouter) Get(path string, handler http.HandlerFunc) {
	r.mux.HandleFunc("GET "+apiPrefix+path, handler)
}

// Post registers handler for "POST /v1<path>".
func (r *apiRouter) Post(path string, handler http.HandlerFunc) {
	r.mux.HandleFunc("POST "+apiPrefix+path, handler)
}

// Delete registers handler for "DELETE /v1<path>".
func (r *apiRouter) Delete(path string, handler http.HandlerFunc) {
	r.mux.HandleFunc("DELETE "+apiPrefix+path, handler)
}

// Patch registers handler for "PATCH /v1<path>".
func (r *apiRouter) Patch(path string, handler http.HandlerFunc) {
	r.mux.HandleFunc("PATCH "+apiPrefix+path, handler)
}

// Config holds public handler configuration.
type Config struct {
	Auth      auth.Config
	CORS      cors.Config
	ONVIF     onvifsvc.Config
	RTSP      rtspsvc.Config
	RateLimit ratelimit.Config
	DemoMode  bool `env:"APP_DEMO_MODE" env-default:"false"`
}

// Router is the HTTP entry point. Domain logic goes through services.
type Router struct {
	config       *Config
	services     *app.Services
	logger       *zap.SugaredLogger
	authLimiter  *ratelimit.Limiter
	authThrottle func(http.Handler) http.Handler
}

// New builds a Router around a constructed service aggregate.
func New(config *Config, services *app.Services, logger *zap.SugaredLogger) *Router {
	limiter := ratelimit.New(config.RateLimit.AuthRPS, config.RateLimit.AuthBurst)

	return &Router{
		config:       config,
		services:     services,
		logger:       logger,
		authLimiter:  limiter,
		authThrottle: ratelimit.PerIP(limiter),
	}
}

// Handler returns the fully wired http.Handler with all middleware applied.
func (h *Router) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /livez", h.pingHandler)
	mux.HandleFunc("GET /readyz", h.healthHandler)

	api := newAPIRouter(mux)

	api.Get("/version", h.versionHandler)

	h.registerAuthAPI(api)
	h.registerMeAPI(api)
	h.registerDashboardAPI(api)
	h.registerSearchAPI(api)
	h.registerHostAPI(api)
	h.registerScanAPI(api)
	h.registerScanScheduleAPI(api)
	h.registerSavedSearchAPI(api)
	h.registerUserAPI(api)
	h.registerDeltaAPI(api)
	h.registerAlertAPI(api)
	h.registerAuditAPI(api)
	h.registerExportAPI(api)
	h.registerCVEAPI(api)
	h.registerPivotAPI(api)
	h.registerRiskAPI(api)

	root := fallback(mux, http.HandlerFunc(h.notFoundHandler))

	chain := chainMiddleware(
		root,
		recovermw.Middleware(h.logger),
		security.Middleware,
		metrics.Middleware(mux),
		loggermw.Middleware(h.logger),
		requestid.Middleware,
		authmw.Middleware(h.config.Auth),
		auditmw.Middleware(h.services.Audit.Repository(), h.logger),
	)

	return cors.Middleware(&h.config.CORS, chain)
}

func (h *Router) notFoundHandler(w http.ResponseWriter, _ *http.Request) {
	h.sendResponse(w, http.StatusNotFound, httperror.CodeNotFound)
}

// chainMiddleware applies mw functions in order so the first argument is the
// outermost middleware (executes first).
func chainMiddleware(base http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	handler := base
	for i := len(mw) - 1; i >= 0; i-- {
		handler = mw[i](handler)
	}

	return handler
}

// fallback returns a handler that delegates to notFound for requests that
// don't match any pattern registered on primary. This keeps the 404 response
// shape consistent with the rest of the API.
func fallback(primary *http.ServeMux, notFound http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := primary.Handler(r)
		if pattern == "" {
			notFound.ServeHTTP(w, r)

			return
		}

		primary.ServeHTTP(w, r)
	})
}

func (h *Router) withDemoGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.config.DemoMode {
			h.sendResponse(w, http.StatusForbidden, httperror.CodeDemoModeRestricted)

			return
		}

		next(w, r)
	}
}

func (h *Router) withRoles(next http.HandlerFunc, allowed ...auth.Role) http.HandlerFunc {
	// An empty allow-list at registration time would silently turn the route
	// into open-for-all-authenticated — a tempting foot-gun. Fail fast at
	// process start so missing role declarations can't slip through.
	if len(allowed) == 0 {
		h.logger.Fatalw("withRoles called with empty allow-list")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		role := auth.RoleFromContext(r.Context())

		for _, candidate := range allowed {
			if role == candidate || (role == auth.RoleAdmin && candidate != "") {
				next(w, r)

				return
			}
		}

		if h.logger != nil {
			h.logger.Warnw("RBAC deny",
				zap.String("role", string(role)),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
			)
		}

		h.sendResponse(w, http.StatusForbidden, httperror.CodeForbidden)
	}
}
