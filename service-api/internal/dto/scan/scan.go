package scan

import (
	"errors"
	"fmt"
	"sort"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmode"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanprofile"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/targetstrategy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// CreateRequest is the payload accepted by POST /v1/scans.
type CreateRequest struct {
	Name           string         `json:"name"            validate:"omitempty,max=256"`
	Target         string         `json:"target"          validate:"omitempty,max=253"`
	Country        string         `json:"country"         validate:"omitempty,iso3166_1_alpha2"`
	ScanSubnet     bool           `json:"scan_subnet"`
	Mode           string         `json:"mode"            validate:"omitempty,oneof=slow masscan zmap"`
	SlowProfile    string         `json:"slow_profile"    validate:"omitempty,oneof=stealth balanced aggressive"`
	TargetStrategy string         `json:"target_strategy" validate:"omitempty,oneof=sequential random country"`
	Limit          uint64         `json:"limit"           validate:"omitempty"`
	PortsExpr      []PortExprItem `json:"ports_expr"      validate:"required,min=1,dive"`
}

// PortExprItem describes one single port or a range.
// For a single port use from == to.
type PortExprItem struct {
	From int32 `json:"from" validate:"required,gt=0,lte=65535"`
	To   int32 `json:"to"   validate:"required,gt=0,lte=65535"`
}

// IsValid validates scan creation request.
func (r *CreateRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate create scan request: %w", err)
	}

	strategy := targetstrategy.Strategy(r.TargetStrategy)

	switch strategy {
	case targetstrategy.Sequential:
		if r.Target == "" {
			return errors.New("target is required for sequential strategy")
		}
	case targetstrategy.Random:
		if r.Limit == 0 {
			return errors.New("limit is required and must be > 0 for random strategy")
		}
	case targetstrategy.Country:
		if r.Country == "" {
			return errors.New("country is required for country strategy")
		}

		if r.Limit == 0 {
			return errors.New("limit is required and must be > 0 for country strategy")
		}

		// Mode is always set by ApplyDefaults before IsValid is called.
		if r.Mode != string(scanmode.Slow) {
			return errors.New("country strategy supports slow engine only")
		}

		if r.Target != "" {
			return errors.New("target must be empty for country strategy")
		}
	}

	if _, err := ParsePortsExpr(r.PortsExpr); err != nil {
		return fmt.Errorf("can't validate create scan ports expression: %w", err)
	}

	return nil
}

// ApplyDefaults fills optional fields with backend defaults without
// transforming user-provided values.
func (r *CreateRequest) ApplyDefaults() {
	if r.Mode == "" {
		r.Mode = string(scanmode.Slow)
	}

	if r.SlowProfile == "" {
		r.SlowProfile = string(scanprofile.Stealth)
	}

	if r.TargetStrategy == "" {
		r.TargetStrategy = string(targetstrategy.Sequential)
	}
}

// ParsePortsExpr expands structured ports/ranges to a unique sorted list.
func ParsePortsExpr(items []PortExprItem) ([]int32, error) {
	if len(items) == 0 {
		return nil, errors.New("ports expression is empty")
	}

	uniq := make(map[int32]struct{})

	for _, item := range items {
		if item.From < 1 || item.From > 65535 || item.To < 1 || item.To > 65535 {
			return nil, errors.New("invalid port")
		}

		if item.From > item.To {
			return nil, errors.New("invalid port range bounds")
		}

		for port := item.From; port <= item.To; port++ {
			uniq[port] = struct{}{}
		}
	}

	if len(uniq) == 0 {
		return nil, errors.New("ports expression has no ports")
	}

	ports := make([]int32, 0, len(uniq))
	for port := range uniq {
		ports = append(ports, port)
	}

	sort.Slice(ports, func(i, j int) bool {
		return ports[i] < ports[j]
	})

	return ports, nil
}

// RecentScannedHost is a host that appeared in the scan snapshot stream.
type RecentScannedHost struct {
	HostID    uint64 `json:"host_id"`
	IP        string `json:"ip"`
	ScannedAt string `json:"scanned_at"`
}

// Scan is the JSON representation of a scan job.
type Scan struct {
	ID              uint64              `json:"id"`
	Name            string              `json:"name,omitempty"`
	CIDR            string              `json:"cidr,omitempty"`
	Country         string              `json:"country,omitempty"`
	PortsExpr       []PortExprItem      `json:"ports_expr"`
	Mode            string              `json:"mode"`
	SlowProfile     string              `json:"slow_profile"`
	TargetStrategy  string              `json:"target_strategy"`
	HostLimit       uint64              `json:"host_limit,omitempty"`
	Status          string              `json:"status"`
	StartedAt       string              `json:"started_at,omitempty"`
	FinishedAt      string              `json:"finished_at,omitempty"`
	Error           string              `json:"error,omitempty"`
	Stats           map[string]any      `json:"stats,omitempty"`
	StatsUpdatedAt  string              `json:"stats_updated_at,omitempty"`
	CreatedAt       string              `json:"created_at"`
	CancelRequested bool                `json:"cancel_requested,omitempty"`
	PauseRequested  bool                `json:"pause_requested,omitempty"`
	HostsScanned    uint64              `json:"hosts_scanned"`
	Progress        *float64            `json:"progress,omitempty"`
	RecentHosts     []RecentScannedHost `json:"recent_hosts,omitempty"`
	ScheduleID      uint64              `json:"schedule_id,omitempty"`
}

// CancelResponse is the wire format of POST /v1/scans/{id}/cancel.
type CancelResponse struct {
	ID     uint64 `json:"id"`
	Status string `json:"status"`
}

// PauseResponse is the wire format of POST /v1/scans/{id}/pause.
type PauseResponse struct {
	ID     uint64 `json:"id"`
	Status string `json:"status"`
}

// ResumeResponse is the wire format of POST /v1/scans/{id}/resume.
type ResumeResponse struct {
	ID     uint64 `json:"id"`
	Status string `json:"status"`
}

// RestartResponse is the wire format of POST /v1/scans/{id}/restart. The id
// is unchanged from the request — restart is in-place: the same scan row is
// reset to PENDING and the worker re-runs it from scratch.
type RestartResponse struct {
	ID     uint64 `json:"id"`
	Status string `json:"status"`
}

// CreateResponse is the wire format of POST /v1/scans.
type CreateResponse struct {
	ScanIDs []uint64 `json:"scan_ids"`
	Queued  int      `json:"queued"`
}

// ListResponse is the wire format of GET /v1/scans.
type ListResponse struct {
	Page  uint64 `json:"page"`
	Limit uint64 `json:"limit"`
	Total uint64 `json:"total"`
	Scans []Scan `json:"scans"`
}
