// Package pause delivers per-scan pause signals via PostgreSQL LISTEN/NOTIFY,
// with a polling fallback if the listener can't connect.
package pause

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
)

// Channel is the PostgreSQL channel used by the trigger uv_scan_pause_notify.
const Channel = "uv_scan_pause"

// PollFallback is the interval at which the listener falls back to polling
// when no LISTEN connection is available.
const PollFallback = 2 * time.Second

// Listener fans out pause notifications from PostgreSQL to per-scan
// subscribers. A single goroutine reads from the LISTEN connection and pushes
// to the matching subscriber channel.
type Listener struct {
	pool           *pgxpool.Pool
	scanRepository scan.Repository
	logger         *zap.SugaredLogger

	mu          sync.Mutex
	subscribers map[uint64]chan struct{}

	pollInterval time.Duration
}

// NewListener builds a pause listener bound to pool.
func NewListener(pool *pgxpool.Pool, scanRepository scan.Repository, logger *zap.SugaredLogger) *Listener {
	return &Listener{
		pool:           pool,
		scanRepository: scanRepository,
		logger:         logger,
		subscribers:    make(map[uint64]chan struct{}),
		pollInterval:   PollFallback,
	}
}

// Run drives the LISTEN goroutine until ctx is canceled. It is safe to call
// Subscribe before Run; deliveries simply block on the buffered channel until
// the listener catches up.
func (l *Listener) Run(ctx context.Context) error {
	backoff := time.Second

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		runErr := l.runOnce(ctx)
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			l.logger.Warnw("Pause listener reconnecting", zap.Error(runErr))
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (l *Listener) runOnce(ctx context.Context) error {
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("can't acquire LISTEN connection: %w", err)
	}

	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return fmt.Errorf("can't issue LISTEN: %w", err)
	}

	l.logger.Infow("Pause listener connected", zap.String("channel", Channel))

	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}

		if notification == nil {
			continue
		}

		scanID, parseErr := strconv.ParseUint(notification.Payload, 10, 64)
		if parseErr != nil {
			l.logger.Warnw("Can't parse pause payload",
				zap.String("payload", notification.Payload),
				zap.Error(parseErr),
			)

			continue
		}

		l.dispatch(scanID)
	}
}

// Subscribe returns a channel that closes when scanID is paused, plus a
// cleanup function the caller must invoke when the scan finishes for any
// reason. Pause polling is run on a side-goroutine as a fallback in case the
// LISTEN connection drops.
func (l *Listener) Subscribe(ctx context.Context, scanID uint64) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)

	l.mu.Lock()
	l.subscribers[scanID] = ch
	l.mu.Unlock()

	pollCtx, stopPolling := context.WithCancel(ctx)
	pollDone := make(chan struct{})

	go func() {
		defer close(pollDone)

		l.poll(pollCtx, scanID, ch)
	}()

	return ch, func() {
		stopPolling()

		<-pollDone

		l.mu.Lock()
		delete(l.subscribers, scanID)
		l.mu.Unlock()
	}
}

func (l *Listener) dispatch(scanID uint64) {
	l.mu.Lock()
	ch, ok := l.subscribers[scanID]
	l.mu.Unlock()

	if !ok {
		return
	}

	select {
	case ch <- struct{}{}:
	default:
	}
}

func (l *Listener) poll(ctx context.Context, scanID uint64, signal chan<- struct{}) {
	ticker := time.NewTicker(l.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		requested, err := l.scanRepository.IsPauseRequested(ctx, scanID)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			l.logger.Debugw("Pause fallback poll failed",
				zap.Uint64("scan_id", scanID),
				zap.Error(err),
			)

			continue
		}

		if requested {
			select {
			case signal <- struct{}{}:
			default:
			}

			return
		}
	}
}
