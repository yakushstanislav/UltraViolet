// Package attackpath carries the wire shapes for /v1/attack-paths/{ip}.
package attackpath

import (
	"encoding/json"
)

// Relation is one edge in the attack-path graph rooted at a host.
type Relation struct {
	SrcHostID    uint64          `json:"src_host_id"`
	DstHostID    uint64          `json:"dst_host_id"`
	RelationType string          `json:"relation_type"`
	Strength     float64         `json:"strength"`
	Evidence     json.RawMessage `json:"evidence,omitempty"`
}

// HostScore is the persisted centrality breakdown for one host.
type HostScore struct {
	HostID                 uint64          `json:"host_id"`
	Centrality             float64         `json:"centrality"`
	PivotScore             float64         `json:"pivot_score"`
	ReachableCriticalCount int32           `json:"reachable_critical_count"`
	TopPaths               json.RawMessage `json:"top_paths,omitempty"`
	ComputedAt             string          `json:"computed_at,omitempty"`
}

// HostRef maps host IDs from relations to concrete IPs.
type HostRef struct {
	HostID uint64 `json:"host_id"`
	IP     string `json:"ip"`
}

// View is the GET /v1/attack-paths/{ip} body.
type View struct {
	IP        string     `json:"ip"`
	Score     HostScore  `json:"score"`
	Hosts     []HostRef  `json:"hosts"`
	Relations []Relation `json:"relations"`
}
