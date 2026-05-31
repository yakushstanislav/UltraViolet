package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	scanrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
	scanservice "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scan"
)

// Channel is the PostgreSQL NOTIFY channel for realtime events.
const Channel = "uv_event"

const (
	snapshotCoalesceMax   = 50
	snapshotCoalesceDelay = time.Second
	statsEnrichCacheTTL   = 200 * time.Millisecond
)

type snapshotHost struct {
	HostID uint64 `json:"host_id"`
	IP     string `json:"ip"`
}

type snapshotCoalescedData struct {
	RecentHosts []snapshotHost `json:"recent_hosts"`
}

type statsEnrichedData struct {
	Stats        map[string]any `json:"stats"`
	HostsScanned uint64         `json:"hosts_scanned"`
	Progress     *float64       `json:"progress"`
}

type pgPayload struct {
	Type   string          `json:"type"`
	ScanID uint64          `json:"scan_id"`
	Data   json.RawMessage `json:"data"`
}

// Listener reads uv_event notifications and publishes to the in-process bus.
type Listener struct {
	pool           *pgxpool.Pool
	scanRepository scanrepository.Repository
	eventsBus      Bus
	logger         *zap.SugaredLogger

	statsMu    sync.Mutex
	statsCache map[uint64]statsCacheEntry

	snapshotMu sync.Mutex
	snapshot   map[uint64]*snapshotBatch
}

type statsCacheEntry struct {
	hostsScanned uint64
	progress     *float64
	expires      time.Time
}

type snapshotBatch struct {
	hosts    []snapshotHost
	timer    *time.Timer
	flushDue time.Time
}

// NewListener builds a PostgreSQL LISTEN consumer.
func NewListener(
	pool *pgxpool.Pool,
	scanRepository scanrepository.Repository,
	eventsBus Bus,
	logger *zap.SugaredLogger,
) *Listener {
	return &Listener{
		pool:           pool,
		scanRepository: scanRepository,
		eventsBus:      eventsBus,
		logger:         logger,
		statsCache:     make(map[uint64]statsCacheEntry),
		snapshot:       make(map[uint64]*snapshotBatch),
	}
}

// Run drives LISTEN until ctx is canceled.
func (l *Listener) Run(ctx context.Context) error {
	backoff := time.Second

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		runErr := l.runOnce(ctx)
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			l.logger.Warnw("Events listener reconnecting", zap.Error(runErr))
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

	l.logger.Infow("Events listener connected", zap.String("channel", Channel))

	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}

		if notification == nil {
			continue
		}

		l.handlePayload(ctx, notification.Payload)
	}
}

func (l *Listener) handlePayload(ctx context.Context, raw string) {
	var payload pgPayload

	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		l.logger.Warnw("Can't parse uv_event payload", zap.String("payload", raw), zap.Error(err))

		return
	}

	switch payload.Type {
	case "scan.snapshot":
		l.coalesceSnapshot(payload)
	case "scan.stats":
		l.publishStats(ctx, payload)
	default:
		l.eventsBus.Publish(Event{
			Type:   payload.Type,
			ScanID: payload.ScanID,
			Ts:     time.Now().UTC(),
			Data:   payload.Data,
		})
	}
}

func (l *Listener) publishStats(ctx context.Context, payload pgPayload) {
	hostsScanned, progress := l.enrichStats(ctx, payload.ScanID)

	var base struct {
		Stats map[string]any `json:"stats"`
	}

	if err := json.Unmarshal(payload.Data, &base); err != nil {
		l.logger.Warnw("Can't parse scan.stats data", zap.Error(err))

		return
	}

	enriched, err := json.Marshal(statsEnrichedData{
		Stats:        base.Stats,
		HostsScanned: hostsScanned,
		Progress:     progress,
	})
	if err != nil {
		l.logger.Warnw("Can't marshal enriched scan.stats", zap.Error(err))

		return
	}

	l.eventsBus.Publish(Event{
		Type:   payload.Type,
		ScanID: payload.ScanID,
		Ts:     time.Now().UTC(),
		Data:   enriched,
	})
}

func (l *Listener) enrichStats(parent context.Context, scanID uint64) (uint64, *float64) {
	now := time.Now()

	l.statsMu.Lock()
	if entry, ok := l.statsCache[scanID]; ok {
		if now.Before(entry.expires) {
			l.statsMu.Unlock()

			return entry.hostsScanned, entry.progress
		}

		delete(l.statsCache, scanID)
	}
	l.statsMu.Unlock()

	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	hostsScanned, err := l.scanRepository.DistinctHostsScanned(ctx, scanID)
	if err != nil {
		l.logger.Debugw("Can't enrich scan.stats", zap.Uint64("scan_id", scanID), zap.Error(err))

		return 0, nil
	}

	scanJob, err := l.scanRepository.GetByID(ctx, scanID)
	if err != nil {
		l.logger.Debugw("Can't load scan for progress", zap.Uint64("scan_id", scanID), zap.Error(err))

		return hostsScanned, nil
	}

	progress := scanservice.ComputeProgress(scanJob)

	l.statsMu.Lock()
	l.statsCache[scanID] = statsCacheEntry{
		hostsScanned: hostsScanned,
		progress:     progress,
		expires:      now.Add(statsEnrichCacheTTL),
	}
	l.statsMu.Unlock()

	return hostsScanned, progress
}

func (l *Listener) coalesceSnapshot(payload pgPayload) {
	var host snapshotHost

	if err := json.Unmarshal(payload.Data, &host); err != nil {
		l.logger.Warnw("Can't parse scan.snapshot data", zap.Error(err))

		return
	}

	l.snapshotMu.Lock()
	defer l.snapshotMu.Unlock()

	batch, ok := l.snapshot[payload.ScanID]
	if !ok {
		batch = &snapshotBatch{}
		l.snapshot[payload.ScanID] = batch
	}

	batch.hosts = append(batch.hosts, host)

	if len(batch.hosts) >= snapshotCoalesceMax {
		l.flushSnapshotLocked(payload.ScanID, batch)

		return
	}

	if batch.timer == nil {
		batch.flushDue = time.Now().Add(snapshotCoalesceDelay)
		scanID := payload.ScanID

		batch.timer = time.AfterFunc(snapshotCoalesceDelay, func() {
			l.snapshotMu.Lock()
			defer l.snapshotMu.Unlock()

			current, exists := l.snapshot[scanID]
			if !exists {
				return
			}

			l.flushSnapshotLocked(scanID, current)
		})
	}
}

func (l *Listener) flushSnapshotLocked(scanID uint64, batch *snapshotBatch) {
	if batch.timer != nil {
		batch.timer.Stop()
		batch.timer = nil
	}

	if len(batch.hosts) == 0 {
		delete(l.snapshot, scanID)

		return
	}

	data, err := json.Marshal(snapshotCoalescedData{RecentHosts: batch.hosts})
	if err != nil {
		l.logger.Warnw("Can't marshal coalesced snapshot", zap.Error(err))

		return
	}

	l.eventsBus.Publish(Event{
		Type:   "scan.snapshot",
		ScanID: scanID,
		Ts:     time.Now().UTC(),
		Data:   data,
	})

	delete(l.snapshot, scanID)
}
