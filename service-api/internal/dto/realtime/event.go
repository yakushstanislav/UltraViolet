// Package realtime defines server→client WebSocket event envelopes.
package realtime

import (
	"encoding/json"
	"time"
)

// Event is the wire envelope for all WebSocket pushes.
type Event struct {
	Type   string          `json:"type"`
	Ts     time.Time       `json:"ts"`
	ScanID uint64          `json:"scan_id,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}
