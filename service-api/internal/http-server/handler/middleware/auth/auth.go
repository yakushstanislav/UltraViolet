// Package auth provides the HTTP middleware that validates bearer JWTs and
// stitches role/user_id into the request context. The token codec, role
// enum, and context helpers live in internal/pkg/auth so the service layer
// doesn't depend on the HTTP layer.
package auth

import (
	"net/http"
	"strings"

	pkgauth "github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
)

// Middleware enforces JWT bearer auth and stores the resolved role/user_id in
// the request context.
func Middleware(config pkgauth.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions || isPublicPath(r.URL.Path) {
				next.ServeHTTP(w, r)

				return
			}

			header := r.Header.Get("Authorization")

			rawToken := strings.TrimPrefix(header, "Bearer ")
			if !strings.HasPrefix(header, "Bearer ") || rawToken == "" {
				writeUnauthorized(w)

				return
			}

			claims, err := pkgauth.ParseAccessToken(config.JWTSecret, rawToken)
			if err != nil || claims.Role == "" || claims.UserID == 0 {
				writeUnauthorized(w)

				return
			}

			ctx := pkgauth.WithRole(r.Context(), claims.Role)
			ctx = pkgauth.WithUserID(ctx, claims.UserID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

func isPublicPath(path string) bool {
	switch path {
	case "/livez", "/readyz",
		"/v1/ping", "/v1/health", "/v1/version",
		"/v1/auth/login", "/v1/auth/refresh":
		return true
	default:
		return false
	}
}
