// Package security sets conservative HTTP response headers.
package security

import "net/http"

// Middleware adds headers that reduce browser-side attack surface.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		next.ServeHTTP(w, r)
	})
}
