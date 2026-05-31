package logger

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/responsewriter"
	loggerpkg "github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/requestid"
)

// Middleware enriches the per-request logger with the request id and packs it
// into the request context.
func Middleware(base *zap.SugaredLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			start := time.Now()

			requestLogger := base.With(
				zap.String("request_id", requestid.UnpackContext(ctx)),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
			)

			ctx = loggerpkg.PackContext(ctx, requestLogger)

			rec := responsewriter.New(w)

			next.ServeHTTP(rec, r.WithContext(ctx))

			requestLogger.Infow("Request completed",
				zap.Int("status", rec.Status),
				zap.Duration("duration", time.Since(start)),
			)
		})
	}
}
