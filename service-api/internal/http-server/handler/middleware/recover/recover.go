// Package recover converts a panic in any downstream handler into a 500
// response so a single nil-deref cannot bring the whole API process down.
package recover

import (
	"net/http"
	"runtime/debug"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
)

// Middleware recovers panics, logs them with a stack trace and writes a
// canonical 500 response. Should be installed as the outermost middleware
// so panics in any inner layer (auth, audit, handlers) are caught.
func Middleware(base *zap.SugaredLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}

				if base != nil {
					base.Errorw("Panic recovered",
						zap.Any("panic", rec),
						zap.String("method", r.Method),
						zap.String("path", r.URL.Path),
						zap.ByteString("stack", debug.Stack()),
					)
				}

				httperror.WriteCode(w, base, http.StatusInternalServerError, httperror.CodeInternal)
			}()

			next.ServeHTTP(w, r)
		})
	}
}
