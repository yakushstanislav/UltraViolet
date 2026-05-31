// Package audit records per-request audit events for write methods.
package audit

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/responsewriter"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	auditrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/audit"
)

const auditWriteTimeout = 5 * time.Second

// trustProxyHeaders controls whether the audit middleware reads the actor IP
// from X-Forwarded-For. When the service is exposed directly, a client can
// trivially spoof this header — so the default is to ignore it and rely on
// RemoteAddr only. Set AUDIT_TRUST_PROXY_HEADERS=true in deployments that
// terminate TLS / proxy through a trusted reverse proxy.
var trustProxyHeaders = strings.EqualFold(os.Getenv("AUDIT_TRUST_PROXY_HEADERS"), "true")

// Middleware persists an audit event for every state-changing request once
// the handler chain returns. Pre-auth login endpoints are skipped because
// failed-credential noise hurts more than it helps.
func Middleware(repo auditrepository.Repository, logger *zap.SugaredLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method := r.Method

			if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
				next.ServeHTTP(w, r)

				return
			}

			recorder := responsewriter.New(w)

			rw := WithResourceHint(r)

			next.ServeHTTP(recorder, rw)

			role := auth.RoleFromContext(rw.Context())
			userIDRaw := auth.UserIDFromContext(rw.Context())

			path := rw.URL.Path

			if strings.HasPrefix(path, "/v1/auth/") {
				return
			}

			event := &auditrepository.Event{
				Method:     method,
				Path:       path,
				StatusCode: recorder.Status,
				ActorIP:    sql.NullString{String: clientIP(rw), Valid: true},
				UserAgent:  sql.NullString{String: rw.Header.Get("User-Agent"), Valid: true},
			}

			if role != "" {
				event.ActorRole = sql.NullString{String: string(role), Valid: true}
			}

			if userIDRaw != 0 {
				event.UserID = sql.NullInt64{Int64: int64(userIDRaw), Valid: true}
			}

			if hint := HintFor(rw); hint != nil && hint.Value != "" {
				event.ResourceID = sql.NullString{String: hint.Value, Valid: true}
			}

			ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
			defer cancel()

			if err := repo.Insert(ctx, event); err != nil {
				logger.Warnw("Can't insert audit event", zap.Error(err), zap.String("path", path))
			}
		})
	}
}

// clientIP returns a best-effort remote IP for the audit row. By default
// the value is taken from r.RemoteAddr; X-Forwarded-For is honored only
// when AUDIT_TRUST_PROXY_HEADERS=true, since an attacker hitting the API
// directly can otherwise spoof the audit trail.
func clientIP(r *http.Request) string {
	if trustProxyHeaders {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if comma := strings.IndexByte(fwd, ','); comma > 0 {
				return strings.TrimSpace(fwd[:comma])
			}

			return strings.TrimSpace(fwd)
		}
	}

	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}

	return host
}
