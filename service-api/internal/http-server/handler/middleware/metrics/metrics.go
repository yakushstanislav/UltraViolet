package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/responsewriter"
)

var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "uv_http_requests_total",
		Help: "Total number of HTTP requests handled by uv-api.",
	}, []string{"method", "path", "status"})

	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "uv_http_request_duration_seconds",
		Help:    "Latency of HTTP requests handled by uv-api.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	requestInFlight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "uv_http_requests_in_flight",
		Help: "Current number of in-flight HTTP requests handled by uv-api.",
	}, []string{"method", "path"})

	responseBytes = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "uv_http_response_size_bytes",
		Help:    "Response body size in bytes for uv-api HTTP responses.",
		Buckets: prometheus.ExponentialBuckets(128, 2, 10),
	}, []string{"method", "path"})
)

// Middleware records request counters and latency histograms. The mux is
// looked up to derive a low-cardinality path label that matches the route
// pattern rather than the raw URL.
func Middleware(mux *http.ServeMux) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			path := routeLabel(mux, r)
			method := r.Method

			requestInFlight.WithLabelValues(method, path).Inc()
			defer requestInFlight.WithLabelValues(method, path).Dec()

			rec := responsewriter.New(w)

			next.ServeHTTP(rec, r)

			duration := time.Since(start).Seconds()
			status := strconv.Itoa(rec.Status)

			requestsTotal.WithLabelValues(method, path, status).Inc()
			requestDuration.WithLabelValues(method, path).Observe(duration)
			responseBytes.WithLabelValues(method, path).Observe(float64(rec.Bytes))
		})
	}
}

func routeLabel(mux *http.ServeMux, r *http.Request) string {
	_, pattern := mux.Handler(r)
	if pattern == "" {
		return "unmatched"
	}

	return pattern
}
