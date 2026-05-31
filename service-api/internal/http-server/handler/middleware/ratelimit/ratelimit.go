// Package ratelimit implements a per-IP token-bucket rate limiter intended
// for unauthenticated endpoints (login, refresh) that are exposed to
// untrusted networks. Buckets are kept in memory and garbage-collected by
// last-access timestamp.
package ratelimit

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

// CodeRateLimited is the wire-error code returned with HTTP 429.
const CodeRateLimited = "rate_limited"

// bucketIdleTTL is how long an idle bucket survives before garbage collection.
const bucketIdleTTL = 30 * time.Minute

// trustProxyHeaders mirrors the audit middleware semantics: only honor
// X-Forwarded-For when the operator opts in via env, so an attacker hitting
// the service directly cannot spoof their bucket key.
var trustProxyHeaders = strings.EqualFold(os.Getenv("AUDIT_TRUST_PROXY_HEADERS"), "true")

// Config holds tunables for the unauthenticated-endpoint rate limiter.
type Config struct {
	AuthRPS   float64 `env:"AUTH_RATE_LIMIT_RPS"   env-default:"1"`
	AuthBurst int     `env:"AUTH_RATE_LIMIT_BURST" env-default:"5"`
}

// Limiter is a thread-safe per-IP token-bucket limiter.
type Limiter struct {
	rps     rate.Limit
	burst   int
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New returns a Limiter configured with the given steady-state rate and
// burst size.
func New(rps float64, burst int) *Limiter {
	return &Limiter{
		rps:     rate.Limit(rps),
		burst:   burst,
		buckets: make(map[string]*bucket),
	}
}

// PerIP wraps the next handler with per-IP throttling. On rejection it
// writes HTTP 429 with the canonical error code.
func PerIP(limiter *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := clientIP(r)

			if !limiter.allow(key) {
				log := logger.UnpackContext(r.Context())

				if log != nil {
					log.Warnw("Rate limited",
						zap.String("client_ip", key),
						zap.String("path", r.URL.Path),
					)
				}

				w.Header().Set("Retry-After", "1")

				httperror.WriteCode(w, log, http.StatusTooManyRequests, CodeRateLimited)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (l *Limiter) allow(key string) bool {
	now := time.Now()

	l.mu.Lock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.buckets[key] = b
	}

	b.lastSeen = now

	if len(l.buckets) > 1024 {
		l.sweepLocked(now)
	}

	allow := b.limiter.Allow()

	l.mu.Unlock()

	return allow
}

func (l *Limiter) sweepLocked(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) > bucketIdleTTL {
			delete(l.buckets, key)
		}
	}
}

// clientIP extracts the request's client IP, honoring X-Forwarded-For only
// when AUDIT_TRUST_PROXY_HEADERS=true.
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
