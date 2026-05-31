// Package scanschedule manages recurring scan schedules.
package scanschedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	scandto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/scan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	scanscheduleRepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scanschedule"
	scanservice "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scan"
)

// ErrNotFound is returned when a schedule does not exist.
var ErrNotFound = scanscheduleRepository.ErrNotFound

// Service orchestrates recurring scan schedules.
type Service struct {
	scheduleRepository scanscheduleRepository.Repository
	scanService        *scanservice.Service
}

// NewService builds a Service.
func NewService(
	scheduleRepository scanscheduleRepository.Repository,
	scanService *scanservice.Service,
) *Service {
	return &Service{
		scheduleRepository: scheduleRepository,
		scanService:        scanService,
	}
}

// Create validates the template, persists the schedule, and enqueues the first run.
func (s *Service) Create(ctx context.Context, req *scandto.CreateScheduleRequest) (*scandto.Schedule, error) {
	req.ApplyDefaults()

	if err := req.IsValid(); err != nil {
		return nil, fmt.Errorf("%w: %w", scanservice.ErrInvalidInput, err)
	}

	if err := s.scanService.Validate(ctx, &req.CreateRequest); err != nil {
		return nil, err
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var hostLimit uint64
	if req.Limit > 0 {
		hostLimit = req.Limit
	}

	createdBy := auth.UserIDFromContext(ctx)

	id, err := s.scheduleRepository.Create(ctx, scanscheduleRepository.CreateParams{
		Name:            req.Name,
		Enabled:         enabled,
		IntervalSeconds: req.IntervalSeconds,
		Target:          req.Target,
		ScanSubnet:      req.ScanSubnet,
		Mode:            req.Mode,
		SlowProfile:     req.SlowProfile,
		TargetStrategy:  req.TargetStrategy,
		HostLimit:       hostLimit,
		PortsExpr:       req.PortsExpr,
		NextRunAt:       time.Now().UTC(),
		CreatedBy:       createdBy,
	})
	if err != nil {
		return nil, err
	}

	schedule, err := s.scheduleRepository.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if enabled {
		if fireErr := s.Fire(ctx, schedule); fireErr != nil {
			if deleteErr := s.scheduleRepository.Delete(ctx, id); deleteErr != nil {
				return nil, fmt.Errorf(
					"can't fire initial schedule run (and rollback delete also failed: %v): %w",
					deleteErr, fireErr,
				)
			}

			return nil, fireErr
		}

		schedule, err = s.scheduleRepository.GetByID(ctx, id)
		if err != nil {
			return nil, err
		}
	}

	return scheduleToDTO(schedule), nil
}

// GetByID returns one schedule.
func (s *Service) GetByID(ctx context.Context, id uint64) (*scandto.Schedule, error) {
	schedule, err := s.scheduleRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, scanscheduleRepository.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	return scheduleToDTO(schedule), nil
}

// List returns a paginated schedule list.
func (s *Service) List(ctx context.Context, page, limit, offset uint64) (*scandto.ScheduleListResponse, error) {
	items, total, err := s.scheduleRepository.List(ctx, limit, offset)
	if err != nil {
		return nil, err
	}

	out := make([]scandto.Schedule, 0, len(items))
	for _, item := range items {
		out = append(out, *scheduleToDTO(item))
	}

	return &scandto.ScheduleListResponse{
		Page:      page,
		Limit:     limit,
		Total:     total,
		Schedules: out,
	}, nil
}

// Update applies a partial patch to a schedule.
func (s *Service) Update(ctx context.Context, id uint64, req *scandto.UpdateScheduleRequest) (*scandto.Schedule, error) {
	if err := req.IsValid(); err != nil {
		return nil, fmt.Errorf("%w: %w", scanservice.ErrInvalidInput, err)
	}

	current, err := s.scheduleRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, scanscheduleRepository.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	patch := scanscheduleRepository.UpdatePatch{
		Name:            req.Name,
		Enabled:         req.Enabled,
		IntervalSeconds: req.IntervalSeconds,
		ScanSubnet:      req.ScanSubnet,
		Mode:            req.Mode,
		SlowProfile:     req.SlowProfile,
		TargetStrategy:  req.TargetStrategy,
		PortsExpr:       req.PortsExpr,
	}

	if req.Target != nil {
		patch.Target = req.Target
	}

	if req.Limit != nil {
		patch.HostLimit = req.Limit
	}

	merged := mergeScheduleTemplate(current, patch)

	if validateErr := s.scanService.Validate(ctx, merged); validateErr != nil {
		return nil, validateErr
	}

	if err := s.scheduleRepository.Update(ctx, id, patch); err != nil {
		if errors.Is(err, scanscheduleRepository.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	return s.GetByID(ctx, id)
}

// SetEnabled toggles whether a schedule fires on its interval.
func (s *Service) SetEnabled(ctx context.Context, id uint64, enabled bool) (*scandto.Schedule, error) {
	if err := s.scheduleRepository.SetEnabled(ctx, id, enabled); err != nil {
		if errors.Is(err, scanscheduleRepository.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	return s.GetByID(ctx, id)
}

// Delete removes a schedule.
func (s *Service) Delete(ctx context.Context, id uint64) error {
	if err := s.scheduleRepository.Delete(ctx, id); err != nil {
		if errors.Is(err, scanscheduleRepository.ErrNotFound) {
			return ErrNotFound
		}

		return err
	}

	return nil
}

// RunNow fires a schedule immediately and advances next_run_at.
func (s *Service) RunNow(ctx context.Context, id uint64) (*scandto.Schedule, error) {
	schedule, err := s.scheduleRepository.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, scanscheduleRepository.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, err
	}

	if err := s.Fire(ctx, schedule); err != nil {
		return nil, err
	}

	return s.GetByID(ctx, id)
}

// Fire enqueues a scan from the stored template and records the next run time.
func (s *Service) Fire(ctx context.Context, schedule *scanscheduleRepository.Schedule) error {
	response, err := s.FireScan(ctx, schedule)
	if err != nil {
		return err
	}

	if len(response.ScanIDs) == 0 {
		return errors.New("scan schedule fire produced no scan ids")
	}

	nextRun := time.Now().UTC().Add(time.Duration(schedule.IntervalSeconds) * time.Second)

	return s.scheduleRepository.RecordRun(ctx, schedule.ID, response.ScanIDs[0], &nextRun)
}

// FireScan enqueues scan jobs without updating schedule bookkeeping.
func (s *Service) FireScan(
	ctx context.Context,
	schedule *scanscheduleRepository.Schedule,
) (*scandto.CreateResponse, error) {
	req := scheduleToCreateRequest(schedule)

	return s.scanService.CreateWithSchedule(ctx, schedule.ID, req)
}

// RecordClaimedRun updates last-run bookkeeping for schedules claimed by the worker.
func (s *Service) RecordClaimedRun(ctx context.Context, scheduleID, scanID uint64) error {
	return s.scheduleRepository.RecordRun(ctx, scheduleID, scanID, nil)
}

func scheduleToCreateRequest(schedule *scanscheduleRepository.Schedule) *scandto.CreateRequest {
	req := &scandto.CreateRequest{
		Name:           schedule.Name,
		ScanSubnet:     schedule.ScanSubnet,
		Mode:           schedule.Mode,
		SlowProfile:    schedule.SlowProfile,
		TargetStrategy: schedule.TargetStrategy,
		PortsExpr:      schedule.PortsExpr,
	}

	if schedule.Target.Valid {
		req.Target = schedule.Target.String
	}

	if schedule.HostLimit.Valid && schedule.HostLimit.Int64 > 0 {
		req.Limit = uint64(schedule.HostLimit.Int64)
	}

	return req
}

func mergeScheduleTemplate(
	current *scanscheduleRepository.Schedule,
	patch scanscheduleRepository.UpdatePatch,
) *scandto.CreateRequest {
	req := scheduleToCreateRequest(current)

	if patch.Target != nil {
		req.Target = *patch.Target
	}

	if patch.ScanSubnet != nil {
		req.ScanSubnet = *patch.ScanSubnet
	}

	if patch.Mode != nil {
		req.Mode = *patch.Mode
	}

	if patch.SlowProfile != nil {
		req.SlowProfile = *patch.SlowProfile
	}

	if patch.TargetStrategy != nil {
		req.TargetStrategy = *patch.TargetStrategy
	}

	if patch.HostLimit != nil {
		req.Limit = *patch.HostLimit
	}

	if len(patch.PortsExpr) > 0 {
		req.PortsExpr = patch.PortsExpr
	}

	req.ApplyDefaults()

	return req
}

func scheduleToDTO(schedule *scanscheduleRepository.Schedule) *scandto.Schedule {
	portsExpr := schedule.PortsExpr
	if portsExpr == nil {
		portsExpr = []scandto.PortExprItem{}
	}

	dto := &scandto.Schedule{
		ID:              schedule.ID,
		Name:            schedule.Name,
		Enabled:         schedule.Enabled,
		IntervalSeconds: schedule.IntervalSeconds,
		ScanSubnet:      schedule.ScanSubnet,
		Mode:            schedule.Mode,
		SlowProfile:     schedule.SlowProfile,
		TargetStrategy:  schedule.TargetStrategy,
		PortsExpr:       portsExpr,
		NextRunAt:       schedule.NextRunAt.UTC().Format(time.RFC3339),
		CreatedAt:       schedule.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:       schedule.UpdatedAt.UTC().Format(time.RFC3339),
	}

	if schedule.Target.Valid {
		dto.Target = schedule.Target.String
	}

	if schedule.HostLimit.Valid && schedule.HostLimit.Int64 > 0 {
		dto.HostLimit = uint64(schedule.HostLimit.Int64)
	}

	if schedule.LastRunAt.Valid {
		dto.LastRunAt = schedule.LastRunAt.Time.UTC().Format(time.RFC3339)
	}

	if schedule.LastScanID.Valid && schedule.LastScanID.Int64 > 0 {
		dto.LastScanID = uint64(schedule.LastScanID.Int64)
	}

	return dto
}
