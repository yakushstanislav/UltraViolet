// Package poolmetrics exports the pgxpool connection-pool statistics as
// Prometheus gauges. The sampler periodically reads pool.Stat() and
// publishes the values; pgx does not provide a collector out of the box.
package poolmetrics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

var (
	openConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "uv_db_connections_open",
		Help: "Currently open pgx pool connections by role",
	}, []string{"service"})

	idleConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "uv_db_connections_idle",
		Help: "Currently idle pgx pool connections by role",
	}, []string{"service"})

	acquiredConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "uv_db_connections_acquired",
		Help: "Currently checked-out pgx pool connections by role",
	}, []string{"service"})

	emptyAcquiresTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "uv_db_acquire_empty_total",
		Help: "Cumulative count of acquires that had to wait for a free conn by role",
	}, []string{"service"})

	maxConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "uv_db_connections_max",
		Help: "Configured pgx pool MaxConns by role",
	}, []string{"service"})
)

// SampleInterval is how often pool stats are refreshed; pgx counters are
// cumulative-but-cheap so polling at 15s aligns with default Prometheus
// scrape cadence.
const SampleInterval = 15 * time.Second

// Run starts a background sampler that updates the pool gauges until ctx
// is cancelled. service labels the metrics (e.g. "uv-api", "uv-scanner").
func Run(ctx context.Context, pool *pgxpool.Pool, service string, logger *zap.SugaredLogger) {
	publish := func() {
		stat := pool.Stat()
		openConnections.WithLabelValues(service).Set(float64(stat.TotalConns()))
		idleConnections.WithLabelValues(service).Set(float64(stat.IdleConns()))
		acquiredConnections.WithLabelValues(service).Set(float64(stat.AcquiredConns()))
		emptyAcquiresTotal.WithLabelValues(service).Set(float64(stat.EmptyAcquireCount()))
		maxConnections.WithLabelValues(service).Set(float64(stat.MaxConns()))
	}

	publish()

	ticker := time.NewTicker(SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if logger != nil {
				logger.Debug("Pool metrics sampler stopped")
			}

			return
		case <-ticker.C:
			publish()
		}
	}
}
