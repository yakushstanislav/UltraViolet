// Package events provides an in-process fan-out bus fed by PostgreSQL LISTEN.
package events

import (
	"encoding/json"
	"sync"
	"time"
)

// Event is the in-process representation of a realtime notification.
type Event struct {
	Type   string          `json:"type"`
	ScanID uint64          `json:"scan_id,omitempty"`
	Ts     time.Time       `json:"ts"`
	Data   json.RawMessage `json:"data,omitempty"`
	ConnID string          `json:"-"`
}

// Bus fans out events to WebSocket subscribers.
type Bus interface {
	Subscribe(scanID uint64, types []string, connID string) (<-chan Event, func())
	Publish(e Event)
}

type subscriber struct {
	scanID uint64
	types  map[string]struct{}
	connID string
	ch     chan Event
	closed bool
}

type memoryBus struct {
	mu          sync.RWMutex
	subscribers map[uint64]*subscriber
	nextID      uint64
}

// NewBus returns a new in-memory event bus.
func NewBus() Bus {
	return &memoryBus{
		subscribers: make(map[uint64]*subscriber),
	}
}

// Subscribe registers for events. scanID 0 means all scans (broadcast types only).
// types filters by event type; empty means all types.
func (b *memoryBus) Subscribe(scanID uint64, types []string, connID string) (<-chan Event, func()) {
	typeSet := make(map[string]struct{}, len(types))
	for _, t := range types {
		typeSet[t] = struct{}{}
	}

	b.mu.Lock()
	b.nextID++

	id := b.nextID

	sub := &subscriber{
		scanID: scanID,
		types:  typeSet,
		connID: connID,
		ch:     make(chan Event, 64),
	}
	b.subscribers[id] = sub
	b.mu.Unlock()

	return sub.ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		if sub.closed {
			return
		}

		sub.closed = true

		delete(b.subscribers, id)
		close(sub.ch)
	}
}

// Publish delivers an event to matching subscribers. Drops when a buffer is full.
// Holds RLock for the duration of the send so the unsubscribe path (which takes
// the write lock) cannot close sub.ch concurrently.
func (b *memoryBus) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sub := range b.subscribers {
		if !sub.matches(e) {
			continue
		}

		select {
		case sub.ch <- e:
		default:
			eventsDroppedTotal.WithLabelValues(sub.connID).Inc()
		}
	}
}

func (s *subscriber) matches(e Event) bool {
	if len(s.types) > 0 {
		if _, ok := s.types[e.Type]; !ok {
			return false
		}
	}

	switch e.Type {
	case "scan.stats", "scan.snapshot":
		return s.scanID != 0 && e.ScanID == s.scanID
	case "alert.fired":
		return true
	default:
		if s.scanID == 0 {
			return true
		}

		return e.ScanID == 0 || e.ScanID == s.scanID
	}
}
