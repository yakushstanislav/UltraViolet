// Package scan manages scan job creation and lifecycle.
package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	scandto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/scan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/countryprefix"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmode"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanpolicy"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanprofile"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/targetstrategy"
	scanrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
)

// ErrInvalidInput is returned when the scan request contains invalid parameters.
var ErrInvalidInput = errors.New("invalid scan input")

// Service orchestrates scan job creation and status management.
type Service struct {
	scanRepository scanrepository.Repository
	scanPolicy     scanpolicy.Config
	countryIndex   *countryprefix.Index
}

// NewService creates a new Service with the given repository and policy.
// countryIndex may be nil — in that case country-strategy scans are rejected
// with an error at validation time. The scanner Pipeline owns the canonical
// index; the API process builds an equivalent one from the same MMDB so it
// can fail fast on validation without going round-trip through the worker.
func NewService(
	scanRepository scanrepository.Repository,
	scanPolicy scanpolicy.Config,
	countryIndex *countryprefix.Index,
) *Service {
	return &Service{
		scanRepository: scanRepository,
		scanPolicy:     scanPolicy,
		countryIndex:   countryIndex,
	}
}

// Create submits a new scan job after validating the request.
func (s *Service) Create(ctx context.Context, req *scandto.CreateRequest) (*scandto.CreateResponse, error) {
	return s.runCreate(ctx, 0, req)
}

// CreateWithSchedule submits a scan job linked to a recurring schedule.
func (s *Service) CreateWithSchedule(
	ctx context.Context,
	scheduleID uint64,
	req *scandto.CreateRequest,
) (*scandto.CreateResponse, error) {
	return s.runCreate(ctx, scheduleID, req)
}

// Validate checks that a scan request would be accepted without persisting jobs.
func (s *Service) Validate(ctx context.Context, req *scandto.CreateRequest) error {
	portsInt32, err := scandto.ParsePortsExpr(req.PortsExpr)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	ports, err := scanpolicy.ConvertPorts(portsInt32)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	strategy := targetstrategy.Strategy(req.TargetStrategy)

	switch strategy {
	case targetstrategy.Random:
		return s.validateRandomScan(req, ports)
	case targetstrategy.Country:
		return s.validateCountryScan(req, ports)
	}

	return s.validateSequentialScan(ctx, req, ports)
}

func (s *Service) runCreate(ctx context.Context, scheduleID uint64, req *scandto.CreateRequest) (*scandto.CreateResponse, error) {
	portsInt32, err := scandto.ParsePortsExpr(req.PortsExpr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	ports, err := scanpolicy.ConvertPorts(portsInt32)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	strategy := targetstrategy.Strategy(req.TargetStrategy)

	switch strategy {
	case targetstrategy.Random:
		return s.createRandomScan(ctx, scheduleID, req, portsInt32, ports)
	case targetstrategy.Country:
		return s.createCountryScan(ctx, scheduleID, req, portsInt32, ports)
	}

	return s.createSequentialScan(ctx, scheduleID, req, portsInt32, ports)
}

func (s *Service) validateSequentialScan(ctx context.Context, req *scandto.CreateRequest, ports []uint16) error {
	cidrs, err := resolveTargets(ctx, req.Target, req.ScanSubnet)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	if req.Mode == string(scanmode.Masscan) || req.Mode == string(scanmode.Zmap) {
		for _, cidr := range cidrs {
			if !cidrIsIPv4(cidr) {
				return fmt.Errorf("masscan and zmap require IPv4 targets: %w", ErrInvalidInput)
			}
		}
	}

	for _, cidr := range cidrs {
		if validationErr := s.scanPolicy.Validate(cidr, ports); validationErr != nil {
			return fmt.Errorf("%s: %w", validationErr.Error(), ErrInvalidInput)
		}
	}

	return nil
}

func (s *Service) validateRandomScan(req *scandto.CreateRequest, ports []uint16) error {
	if req.Limit == 0 {
		return fmt.Errorf("limit is required and must be > 0 for random strategy: %w", ErrInvalidInput)
	}

	if s.scanPolicy.AllowedCIDRs == "" {
		return fmt.Errorf("random strategy requires SCAN_ALLOWED_CIDRS to be configured: %w", ErrInvalidInput)
	}

	if s.scanPolicy.MaxHosts > 0 && req.Limit > s.scanPolicy.MaxHosts {
		return fmt.Errorf("limit exceeds SCAN_MAX_HOSTS policy: %w", ErrInvalidInput)
	}

	if err := s.scanPolicy.ValidatePorts(ports); err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	return nil
}

func (s *Service) createSequentialScan(
	ctx context.Context,
	scheduleID uint64,
	req *scandto.CreateRequest,
	portsInt32 []int32,
	ports []uint16,
) (*scandto.CreateResponse, error) {
	cidrs, err := resolveTargets(ctx, req.Target, req.ScanSubnet)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	if req.Mode == string(scanmode.Masscan) || req.Mode == string(scanmode.Zmap) {
		for _, cidr := range cidrs {
			if !cidrIsIPv4(cidr) {
				return nil, fmt.Errorf("masscan and zmap require IPv4 targets: %w", ErrInvalidInput)
			}
		}
	}

	scanIDs := make([]uint64, 0, len(cidrs))

	for _, cidr := range cidrs {
		if validationErr := s.scanPolicy.Validate(cidr, ports); validationErr != nil {
			return nil, fmt.Errorf("%s: %w", validationErr.Error(), ErrInvalidInput)
		}

		scanJob := &scanrepository.Scan{
			CIDR:           sql.NullString{String: cidr, Valid: true},
			Ports:          portsInt32,
			PortsExpr:      req.PortsExpr,
			Mode:           req.Mode,
			SlowProfile:    req.SlowProfile,
			TargetStrategy: req.TargetStrategy,
		}

		if req.Limit > 0 {
			scanJob.HostLimit = sql.NullInt64{Int64: int64(req.Limit), Valid: true}
		}

		if req.Name != "" {
			scanJob.Name = sql.NullString{String: req.Name, Valid: true}
		}

		if scheduleID > 0 {
			scanJob.ScheduleID = sql.NullInt64{Int64: int64(scheduleID), Valid: true}
		}

		id, createErr := s.scanRepository.Create(ctx, scanJob)
		if createErr != nil {
			return nil, createErr
		}

		scanIDs = append(scanIDs, id)
	}

	return &scandto.CreateResponse{
		ScanIDs: scanIDs,
		Queued:  len(scanIDs),
	}, nil
}

func (s *Service) createRandomScan(
	ctx context.Context,
	scheduleID uint64,
	req *scandto.CreateRequest,
	portsInt32 []int32,
	ports []uint16,
) (*scandto.CreateResponse, error) {
	if req.Limit == 0 {
		return nil, fmt.Errorf("limit is required and must be > 0 for random strategy: %w", ErrInvalidInput)
	}

	if s.scanPolicy.AllowedCIDRs == "" {
		return nil, fmt.Errorf("random strategy requires SCAN_ALLOWED_CIDRS to be configured: %w", ErrInvalidInput)
	}

	if s.scanPolicy.MaxHosts > 0 && req.Limit > s.scanPolicy.MaxHosts {
		return nil, fmt.Errorf("limit exceeds SCAN_MAX_HOSTS policy: %w", ErrInvalidInput)
	}

	if err := s.scanPolicy.ValidatePorts(ports); err != nil {
		return nil, fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	scanJob := &scanrepository.Scan{
		Ports:          portsInt32,
		PortsExpr:      req.PortsExpr,
		Mode:           req.Mode,
		SlowProfile:    req.SlowProfile,
		TargetStrategy: req.TargetStrategy,
		HostLimit:      sql.NullInt64{Int64: int64(req.Limit), Valid: true},
	}

	if req.Name != "" {
		scanJob.Name = sql.NullString{String: req.Name, Valid: true}
	}

	if scheduleID > 0 {
		scanJob.ScheduleID = sql.NullInt64{Int64: int64(scheduleID), Valid: true}
	}

	id, err := s.scanRepository.Create(ctx, scanJob)
	if err != nil {
		return nil, err
	}

	return &scandto.CreateResponse{
		ScanIDs: []uint64{id},
		Queued:  1,
	}, nil
}

func (s *Service) validateCountryScan(req *scandto.CreateRequest, ports []uint16) error {
	if req.Mode != string(scanmode.Slow) {
		return fmt.Errorf("country strategy supports slow engine only: %w", ErrInvalidInput)
	}

	if req.Country == "" {
		return fmt.Errorf("country is required for country strategy: %w", ErrInvalidInput)
	}

	if req.Limit == 0 {
		return fmt.Errorf("limit is required and must be > 0 for country strategy: %w", ErrInvalidInput)
	}

	if s.scanPolicy.MaxHosts > 0 && req.Limit > s.scanPolicy.MaxHosts {
		return fmt.Errorf("limit exceeds SCAN_MAX_HOSTS policy: %w", ErrInvalidInput)
	}

	if s.countryIndex == nil || s.countryIndex.Len() == 0 {
		return fmt.Errorf("country strategy requires GeoIP country database: %w", ErrInvalidInput)
	}

	if len(s.countryIndex.Prefixes(req.Country)) == 0 {
		return fmt.Errorf("country %q has no IPv4 prefixes in GeoIP database: %w", req.Country, ErrInvalidInput)
	}

	if err := s.scanPolicy.ValidatePorts(ports); err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrInvalidInput)
	}

	return nil
}

func (s *Service) createCountryScan(
	ctx context.Context,
	scheduleID uint64,
	req *scandto.CreateRequest,
	portsInt32 []int32,
	ports []uint16,
) (*scandto.CreateResponse, error) {
	if err := s.validateCountryScan(req, ports); err != nil {
		return nil, err
	}

	scanJob := &scanrepository.Scan{
		Country:        sql.NullString{String: req.Country, Valid: true},
		Ports:          portsInt32,
		PortsExpr:      req.PortsExpr,
		Mode:           req.Mode,
		SlowProfile:    req.SlowProfile,
		TargetStrategy: req.TargetStrategy,
		HostLimit:      sql.NullInt64{Int64: int64(req.Limit), Valid: true},
	}

	if req.Name != "" {
		scanJob.Name = sql.NullString{String: req.Name, Valid: true}
	}

	if scheduleID > 0 {
		scanJob.ScheduleID = sql.NullInt64{Int64: int64(scheduleID), Valid: true}
	}

	id, err := s.scanRepository.Create(ctx, scanJob)
	if err != nil {
		return nil, err
	}

	return &scandto.CreateResponse{
		ScanIDs: []uint64{id},
		Queued:  1,
	}, nil
}

// GetByID returns a scan job by its primary key.
func (s *Service) GetByID(ctx context.Context, id uint64) (*scandto.Scan, error) {
	scanJob, err := s.scanRepository.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	dto := scanToDTO(scanJob)

	hostsScanned, err := s.scanRepository.DistinctHostsScanned(ctx, id)
	if err != nil {
		return nil, err
	}

	dto.HostsScanned = hostsScanned
	dto.Progress = ComputeProgress(scanJob)
	dto.Stats = EnrichStatsHostsScanned(dto.Stats, hostsScanned)

	recent, err := s.scanRepository.RecentScannedHosts(ctx, id, 10)
	if err != nil {
		return nil, err
	}

	if len(recent) > 0 {
		dto.RecentHosts = make([]scandto.RecentScannedHost, 0, len(recent))
		for _, row := range recent {
			dto.RecentHosts = append(dto.RecentHosts, scandto.RecentScannedHost{
				HostID:    row.HostID,
				IP:        row.IP,
				ScannedAt: row.ScannedAt.UTC().Format(time.RFC3339),
			})
		}
	}

	return &dto, nil
}

// RequestCancel requests cancellation of a running scan.
func (s *Service) RequestCancel(ctx context.Context, id uint64) (*scandto.CancelResponse, error) {
	status, err := s.scanRepository.RequestCancel(ctx, id)
	if err != nil {
		return nil, err
	}

	return &scandto.CancelResponse{
		ID:     id,
		Status: string(status),
	}, nil
}

// RequestPause requests pausing a running scan. The worker observes the flag
// and finalises the scan with status PAUSED so it can be resumed later.
//
// Pause is not supported when target_strategy=random is combined with the
// masscan or zmap engines: those engines run atomically as a subprocess over
// a pre-materialised IP list, so there is no mid-run cursor to persist.
func (s *Service) RequestPause(ctx context.Context, id uint64) (*scandto.PauseResponse, error) {
	scanJob, err := s.scanRepository.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if scanJob.TargetStrategy == string(targetstrategy.Random) &&
		(scanJob.Mode == string(scanmode.Masscan) || scanJob.Mode == string(scanmode.Zmap)) {
		return nil, fmt.Errorf("pause is not supported for random + masscan/zmap: %w", ErrInvalidInput)
	}

	status, err := s.scanRepository.RequestPause(ctx, id)
	if err != nil {
		return nil, err
	}

	return &scandto.PauseResponse{
		ID:     id,
		Status: string(status),
	}, nil
}

// RequestResume re-enables a paused scan (or cancels a pending pause request
// on a still-running scan). When the scan is PAUSED the worker will pick it
// up again on its next tick via the queue Claim.
func (s *Service) RequestResume(ctx context.Context, id uint64) (*scandto.ResumeResponse, error) {
	status, err := s.scanRepository.RequestResume(ctx, id)
	if err != nil {
		return nil, err
	}

	return &scandto.ResumeResponse{
		ID:     id,
		Status: string(status),
	}, nil
}

// Restart resets a scan in-place so the worker re-runs it under the same id.
// All artefacts of previous runs (snapshots, change events, delta summary)
// are dropped; the scan goes back to PENDING. Only terminal scans
// (DONE/FAILED/CANCELED) and PAUSED scans are eligible — RUNNING and PENDING
// scans return ErrNotRestartable (the caller should stop or wait first).
func (s *Service) Restart(ctx context.Context, id uint64) (*scandto.RestartResponse, error) {
	status, err := s.scanRepository.Restart(ctx, id)
	if err != nil {
		return nil, err
	}

	return &scandto.RestartResponse{
		ID:     id,
		Status: string(status),
	}, nil
}

// GetAll returns a paginated list of scan jobs.
func (s *Service) GetAll(ctx context.Context, page, limit, offset uint64, sortColumn string, sortDesc bool) (*scandto.ListResponse, error) {
	scans, total, err := s.scanRepository.GetAll(ctx, limit, offset, sortColumn, sortDesc)
	if err != nil {
		return nil, err
	}

	response := &scandto.ListResponse{
		Page:  page,
		Limit: limit,
		Total: total,
		Scans: make([]scandto.Scan, 0, len(scans)),
	}

	for _, item := range scans {
		response.Scans = append(response.Scans, scanToDTO(item))
	}

	return response, nil
}

func scanToDTO(s *scanrepository.Scan) scandto.Scan {
	portsExpr := s.PortsExpr
	if portsExpr == nil {
		portsExpr = []scandto.PortExprItem{}
	}

	strategy := s.TargetStrategy
	if strategy == "" {
		strategy = string(targetstrategy.Sequential)
	}

	profile := s.SlowProfile
	if profile == "" {
		profile = string(scanprofile.Stealth)
	}

	dto := scandto.Scan{
		ID:              s.ID,
		PortsExpr:       portsExpr,
		Mode:            s.Mode,
		SlowProfile:     profile,
		TargetStrategy:  strategy,
		Status:          string(s.Status),
		Stats:           s.Stats,
		CreatedAt:       s.CreatedAt.Format(time.RFC3339),
		CancelRequested: s.CancelRequested,
		PauseRequested:  s.PauseRequested,
	}

	if s.CIDR.Valid {
		dto.CIDR = s.CIDR.String
	}

	if s.Country.Valid {
		dto.Country = s.Country.String
	}

	if s.HostLimit.Valid && s.HostLimit.Int64 > 0 {
		dto.HostLimit = uint64(s.HostLimit.Int64)
	}

	if s.Name.Valid {
		dto.Name = s.Name.String
	}

	if s.ScheduleID.Valid && s.ScheduleID.Int64 > 0 {
		dto.ScheduleID = uint64(s.ScheduleID.Int64)
	}

	if s.StartedAt.Valid {
		dto.StartedAt = s.StartedAt.Time.Format(time.RFC3339)
	}

	if s.FinishedAt.Valid {
		dto.FinishedAt = s.FinishedAt.Time.Format(time.RFC3339)
	}

	if s.Error.Valid {
		dto.Error = s.Error.String
	}

	if s.StatsUpdatedAt.Valid {
		dto.StatsUpdatedAt = s.StatsUpdatedAt.Time.Format(time.RFC3339)
	}

	return dto
}

func resolveTargets(ctx context.Context, rawTarget string, scanSubnet bool) ([]string, error) {
	target := rawTarget
	if target == "" {
		return nil, errors.New("target is empty")
	}

	if prefix, err := netip.ParsePrefix(target); err == nil {
		if scanSubnet {
			return []string{prefix.Masked().String()}, nil
		}

		host := prefix.Addr()

		return []string{netip.PrefixFrom(host, host.BitLen()).Masked().String()}, nil
	}

	if addr, err := netip.ParseAddr(target); err == nil {
		return []string{singleIPPrefix(addr, scanSubnet).String()}, nil
	}

	// Bound DNS lookups even when the caller passes a deadline-less context
	// (e.g. a background job). Without this the system resolver may hang
	// for tens of seconds on hostile upstreams, holding the calling API
	// goroutine open.
	lookupCtx, lookupCancel := context.WithTimeout(ctx, 5*time.Second)
	defer lookupCancel()

	resolved, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", target)
	if err != nil {
		return nil, fmt.Errorf("can't resolve target host: %w", err)
	}

	uniq := make(map[string]struct{}, len(resolved))
	out := make([]string, 0, len(resolved))

	for _, addr := range resolved {
		if !addr.IsValid() {
			continue
		}

		prefix := singleIPPrefix(addr, scanSubnet).String()
		if _, exists := uniq[prefix]; exists {
			continue
		}

		uniq[prefix] = struct{}{}
		out = append(out, prefix)
	}

	if len(out) == 0 {
		return nil, errors.New("target host resolved to no valid IP addresses")
	}

	return out, nil
}

func cidrIsIPv4(cidr string) bool {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}

	return prefix.Addr().Is4()
}

func singleIPPrefix(addr netip.Addr, scanSubnet bool) netip.Prefix {
	if scanSubnet {
		bits := 64
		if addr.Is4() {
			bits = 24
		}

		return netip.PrefixFrom(addr, bits).Masked()
	}

	return netip.PrefixFrom(addr, addr.BitLen())
}
