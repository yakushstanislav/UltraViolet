package requestid

import (
	"net/http"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/requestid"
)

const (
	headerName       = "X-Request-Id"
	maxRequestIDLen  = 128
	requestIDCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		"_-."
)

// Middleware injects a request id into the context and response header.
// Client-supplied IDs are validated against a tight charset/length so a
// poisoned header can't be reflected into structured logs or audit rows
// with control characters.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(headerName)
		if !validRequestID(id) {
			id = requestid.New()
		}

		w.Header().Set(headerName, id)

		ctx := requestid.PackContext(r.Context(), id)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}

	for i := range len(id) {
		c := id[i]
		if !inCharset(c) {
			return false
		}
	}

	return true
}

func inCharset(c byte) bool {
	for i := range len(requestIDCharset) {
		if requestIDCharset[i] == c {
			return true
		}
	}

	return false
}
