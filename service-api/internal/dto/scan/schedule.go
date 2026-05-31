package scan

import (
	"errors"
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/targetstrategy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// CreateScheduleRequest is the payload accepted by POST /v1/scan-schedules.
type CreateScheduleRequest struct {
	CreateRequest
	Name            string `json:"name"             validate:"required,max=256"`
	IntervalSeconds int    `json:"interval_seconds" validate:"required,gte=300"`
	Enabled         *bool  `json:"enabled"`
}

// UpdateScheduleRequest is the payload accepted by PATCH /v1/scan-schedules/{id}.
type UpdateScheduleRequest struct {
	Name            *string        `json:"name,omitempty"             validate:"omitempty,max=256"`
	Target          *string        `json:"target,omitempty"           validate:"omitempty,max=253"`
	ScanSubnet      *bool          `json:"scan_subnet,omitempty"`
	Mode            *string        `json:"mode,omitempty"             validate:"omitempty,oneof=slow masscan zmap"`
	SlowProfile     *string        `json:"slow_profile,omitempty"     validate:"omitempty,oneof=stealth balanced aggressive"`
	TargetStrategy  *string        `json:"target_strategy,omitempty"  validate:"omitempty,oneof=sequential random"`
	Limit           *uint64        `json:"limit,omitempty"`
	PortsExpr       []PortExprItem `json:"ports_expr,omitempty"       validate:"omitempty,min=1,dive"`
	IntervalSeconds *int           `json:"interval_seconds,omitempty" validate:"omitempty,gte=300"`
	Enabled         *bool          `json:"enabled,omitempty"`
}

// SetScheduleEnabledRequest is the payload accepted by PATCH /v1/scan-schedules/{id}/enabled.
type SetScheduleEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

// IsValid satisfies the project's request-validation convention. There is no
// real structural constraint on a single bool field, so this always passes;
// the method exists so the handler call site looks uniform and any future
// field addition gets validated by default rather than slipping through.
func (r *SetScheduleEnabledRequest) IsValid() error {
	return nil
}

// Schedule is the wire representation of a recurring scan schedule.
type Schedule struct {
	ID              uint64         `json:"id"`
	Name            string         `json:"name"`
	Enabled         bool           `json:"enabled"`
	IntervalSeconds int            `json:"interval_seconds"`
	Target          string         `json:"target,omitempty"`
	ScanSubnet      bool           `json:"scan_subnet"`
	Mode            string         `json:"mode"`
	SlowProfile     string         `json:"slow_profile"`
	TargetStrategy  string         `json:"target_strategy"`
	HostLimit       uint64         `json:"host_limit,omitempty"`
	PortsExpr       []PortExprItem `json:"ports_expr"`
	LastRunAt       string         `json:"last_run_at,omitempty"`
	LastScanID      uint64         `json:"last_scan_id,omitempty"`
	NextRunAt       string         `json:"next_run_at"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
}

// ScheduleListResponse is the wire format of GET /v1/scan-schedules.
type ScheduleListResponse struct {
	Page      uint64     `json:"page"`
	Limit     uint64     `json:"limit"`
	Total     uint64     `json:"total"`
	Schedules []Schedule `json:"schedules"`
}

// IsValid validates schedule creation request.
func (r *CreateScheduleRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate create scan schedule request: %w", err)
	}

	r.ApplyDefaults()

	if err := r.CreateRequest.IsValid(); err != nil {
		return fmt.Errorf("can't validate scan template: %w", err)
	}

	if r.TargetStrategy == string(targetstrategy.Country) {
		return errors.New("country strategy is not supported in scan schedules yet")
	}

	return nil
}

// IsValid validates schedule update request.
func (r *UpdateScheduleRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate update scan schedule request: %w", err)
	}

	if len(r.PortsExpr) > 0 {
		if _, err := ParsePortsExpr(r.PortsExpr); err != nil {
			return fmt.Errorf("can't validate ports expression: %w", err)
		}
	}

	return nil
}
