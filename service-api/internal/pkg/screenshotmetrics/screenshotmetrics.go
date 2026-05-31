// Package screenshotmetrics exposes Prometheus instrumentation for the HTTP
// screenshot worker: per-status attempt counter, render-duration histogram,
// thumbnail-size histogram and queue-depth gauge.
package screenshotmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AttemptsTotal counts render attempts by terminal outcome.
//
//	success         — JPEG produced and stored.
//	timeout         — Page.loadEventFired didn't arrive in time.
//	render_error    — Chromium returned a CDP error.
//	network_error   — failure reaching the Chromium debugger socket.
var AttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "uv_http_screenshot_attempts_total",
	Help: "HTTP screenshot render attempts by outcome",
}, []string{"status"})

// DurationSeconds records render wall-clock time.
var DurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "uv_http_screenshot_duration_seconds",
	Help:    "Wall-clock duration of one screenshot render",
	Buckets: prometheus.ExponentialBuckets(0.5, 2, 8),
})

// SizeBytes records compressed JPEG size of stored thumbnails.
var SizeBytes = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "uv_http_screenshot_size_bytes",
	Help:    "Compressed size of stored screenshot thumbnails",
	Buckets: prometheus.ExponentialBuckets(1024, 2, 12),
})

// QueueDepth reflects pending/running/failed job counts published by a
// background sampler in the worker.
var QueueDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "uv_http_screenshot_queue_depth",
	Help: "Number of screenshot jobs in each status (pending, running, failed)",
}, []string{"status"})
