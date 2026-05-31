package host

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/riskmetrics"
)

// RecomputeQueueConfig controls the in-process debounced recompute queue.
// The queue exists so high-frequency triggers (CVE matcher bursts, ingest
// storms) coalesce into one recompute per host inside the debounce window
// instead of N back-to-back rescores of the same host.
type RecomputeQueueConfig struct {
	Enabled  bool          `env:"RISK_RECOMPUTE_QUEUE_ENABLED" env-default:"true"`
	Debounce time.Duration `env:"RISK_RECOMPUTE_DEBOUNCE"      env-default:"2s"`
	Workers  int           `env:"RISK_RECOMPUTE_WORKERS"       env-default:"4"`
}

// RecomputeQueue debounces host recomputes: repeated Enqueue(hostID)
// inside the debounce window collapses into a single AggregateForHost
// call. A pool of workers drains the queue concurrently so unrelated
// hosts process in parallel. The type also satisfies the matcher's
// HostRiskAggregator interface so callers that hold a *RecomputeQueue
// transparently get debounced recomputes instead of synchronous ones.
type RecomputeQueue struct {
	cfg    RecomputeQueueConfig
	risk   *RiskService
	logger *zap.SugaredLogger

	mu      sync.Mutex
	pending map[uint64]time.Time
	signal  chan struct{}

	// running flips to true the moment Run starts its worker pool, so
	// Enqueue can detect environments where nothing drains the queue
	// (e.g. uv-scanner one-shot scan mode) and fall back to synchronous
	// AggregateForHost instead of silently dropping work.
	running atomic.Bool
}

// NewRecomputeQueue builds a queue bound to risk. Workers start on Run.
func NewRecomputeQueue(cfg RecomputeQueueConfig, risk *RiskService, logger *zap.SugaredLogger) *RecomputeQueue {
	if cfg.Debounce <= 0 {
		cfg.Debounce = 2 * time.Second
	}

	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}

	return &RecomputeQueue{
		cfg:     cfg,
		risk:    risk,
		logger:  logger,
		pending: make(map[uint64]time.Time, 64),
		signal:  make(chan struct{}, 1),
	}
}

// Enqueue records a recompute request for hostID. Returns immediately —
// the actual AggregateForHost call happens on a worker goroutine after
// the debounce window elapses. The trigger label is preserved in ctx so
// the metrics counter still partitions correctly.
func (q *RecomputeQueue) Enqueue(ctx context.Context, hostID uint64) {
	if !q.cfg.Enabled || !q.running.Load() {
		// Pass-through: queue is disabled by config or Run has not been
		// called yet (e.g. one-shot scan). Behave like the legacy
		// synchronous hot path so no work is dropped.
		if err := q.risk.AggregateForHost(ctx, hostID); err != nil {
			q.logger.Warnw("Recompute failed (queue pass-through)",
				zap.Uint64("host_id", hostID),
				zap.Error(err),
			)
		}

		return
	}

	q.mu.Lock()
	q.pending[hostID] = time.Now().Add(q.cfg.Debounce)
	q.mu.Unlock()

	select {
	case q.signal <- struct{}{}:
	default:
	}
}

// AggregateForHost satisfies the matcher's HostRiskAggregator interface
// by enqueuing instead of recomputing synchronously. Always returns nil
// because dispatch is deferred to the worker pool; failures are logged
// inside worker().
func (q *RecomputeQueue) AggregateForHost(ctx context.Context, hostID uint64) error {
	q.Enqueue(ctx, hostID)

	return nil
}

// AggregateForService resolves the owning host once and enqueues — the
// service→host lookup must stay synchronous because the caller's only
// link to the host is the service ID.
func (q *RecomputeQueue) AggregateForService(ctx context.Context, serviceID uint64) error {
	hostID, err := q.risk.HostIDForService(ctx, serviceID)
	if err != nil {
		return err
	}

	q.Enqueue(ctx, hostID)

	return nil
}

// Run starts the worker pool. Returns when ctx is canceled. Caller
// typically wires it under errgroup alongside the other long-running
// loops in cmd/uv-scanner/main.go.
func (q *RecomputeQueue) Run(ctx context.Context) error {
	if !q.cfg.Enabled {
		<-ctx.Done()

		return ctx.Err()
	}

	q.running.Store(true)
	defer q.running.Store(false)

	work := make(chan uint64, 256)

	var wg sync.WaitGroup

	for range q.cfg.Workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			q.worker(ctx, work)
		}()
	}

	ticker := time.NewTicker(q.cfg.Debounce / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			close(work)
			wg.Wait()

			return ctx.Err()
		case <-q.signal:
			q.drainReady(work)
		case <-ticker.C:
			q.drainReady(work)
		}
	}
}

// drainReady moves every host whose debounce window has elapsed onto the
// work channel. Holding the lock for the full scan is fine — the map is
// typically small (10s of pending hosts) because of the coalescing.
func (q *RecomputeQueue) drainReady(work chan<- uint64) {
	now := time.Now()

	q.mu.Lock()

	ready := make([]uint64, 0, len(q.pending))

	for hostID, due := range q.pending {
		if !due.After(now) {
			ready = append(ready, hostID)
			delete(q.pending, hostID)
		}
	}

	q.mu.Unlock()

	for _, hostID := range ready {
		select {
		case work <- hostID:
		default:
			// Worker pool saturated — put it back so the next tick retries.
			q.mu.Lock()
			q.pending[hostID] = time.Now().Add(q.cfg.Debounce)
			q.mu.Unlock()
		}
	}
}

// worker pulls from the work channel and calls AggregateForHost. Trigger
// label defaults to "queued" so dashboards can tell queued recomputes
// apart from synchronous ones.
func (q *RecomputeQueue) worker(ctx context.Context, work <-chan uint64) {
	for hostID := range work {
		workerCtx := WithTrigger(ctx, riskmetrics.TriggerQueued)

		if err := q.risk.AggregateForHost(workerCtx, hostID); err != nil {
			q.logger.Warnw("Queued recompute failed",
				zap.Uint64("host_id", hostID),
				zap.Error(err),
			)
		}
	}
}
