// Package cors provides CORS headers for the browser-based frontend.
package cors

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	allowMethods  = "GET, POST, PATCH, DELETE, OPTIONS"
	allowHeaders  = "Authorization, Content-Type, X-Request-Id"
	exposeHeaders = "X-Request-Id, X-UV-RTSP-Snapshot-Path"
	maxAge        = "600"
)

// Config controls browser origins that may call the API.
type Config struct {
	AllowedOrigins string `env:"CORS_ALLOWED_ORIGINS" env-default:"http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"`
}

// loopbackDevOriginPatterns authorizes WebSocket Origin headers for IPv4 127.0.0.0/8 with
// common SPA dev ports. Covers Vite on 0.0.0.0, preview (:4173), and port-forwarded URLs
// (e.g. http://127.191.208.128:5173) where the page origin is not localhost/127.0.0.1.
// github.com/coder/websocket matches these with path.Match; only client loopback is in range.
var loopbackDevOriginPatterns = []string{
	"http://127.*.*.*:5173",
	"https://127.*.*.*:5173",
	"http://127.*.*.*:3000",
	"https://127.*.*.*:3000",
	"http://127.*.*.*:4173",
	"https://127.*.*.*:4173",
	"127.*.*.*:5173",
	"127.*.*.*:3000",
	"127.*.*.*:4173",
}

// Middleware allows the SPA to call the API directly from localhost or nginx.
func Middleware(config *Config, next http.Handler) http.Handler {
	allowedOrigins := parseAllowedOrigins(config)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowedOrigin, ok := matchOrigin(origin, allowedOrigins)
			if !ok {
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)

					return
				}

				next.ServeHTTP(w, r)

				return
			}

			header := w.Header()
			header.Set("Access-Control-Allow-Origin", allowedOrigin)
			header.Set("Access-Control-Allow-Methods", allowMethods)
			header.Set("Access-Control-Allow-Headers", allowHeaders)
			header.Set("Access-Control-Expose-Headers", exposeHeaders)
			header.Set("Access-Control-Max-Age", maxAge)
			header.Add("Vary", "Origin")
			header.Add("Vary", "Access-Control-Request-Method")
			header.Add("Vary", "Access-Control-Request-Headers")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// OriginPatterns returns allowed browser origins for WebSocket handshakes.
func OriginPatterns(config *Config) []string {
	origins := parseAllowedOrigins(config)
	patterns := make([]string, 0, len(origins)*2+len(loopbackDevOriginPatterns))

	for _, origin := range origins {
		patterns = append(patterns, origin)

		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" {
			continue
		}

		patterns = append(patterns, parsed.Host)
	}

	patterns = append(patterns, loopbackDevOriginPatterns...)

	return patterns
}

func parseAllowedOrigins(config *Config) []string {
	if config == nil || config.AllowedOrigins == "" {
		return nil
	}

	parts := strings.Split(config.AllowedOrigins, ",")
	origins := make([]string, 0, len(parts))

	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}

		// Reject the literal wildcard so a misconfigured deployment can't
		// accidentally turn into an open CORS policy. Operators that genuinely
		// want allow-all should enumerate origins or remove CORS entirely.
		if origin == "*" {
			continue
		}

		origins = append(origins, origin)
	}

	return origins
}

func matchOrigin(origin string, allowed []string) (string, bool) {
	for _, candidate := range allowed {
		if candidate == origin {
			return origin, true
		}
	}

	return "", false
}
