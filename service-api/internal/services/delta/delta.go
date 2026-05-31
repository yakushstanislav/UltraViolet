// Package delta exposes scan change summaries and timelines.
package delta

import (
	"context"
	"net/netip"

	deltarepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/delta"
)

// Service wraps delta persistence for the HTTP API.
type Service struct {
	deltaRepository deltarepository.Repository
}

// NewService builds a Service.
func NewService(deltaRepository deltarepository.Repository) *Service {
	return &Service{deltaRepository: deltaRepository}
}

// GetSummary returns aggregated change counts for one scan.
func (s *Service) GetSummary(ctx context.Context, scanID uint64) (*deltarepository.Summary, error) {
	return s.deltaRepository.GetSummary(ctx, scanID)
}

// GetHostTimeline returns change events for one host IP.
func (s *Service) GetHostTimeline(
	ctx context.Context,
	ip netip.Addr,
	limit, offset uint64,
) ([]*deltarepository.ChangeEvent, uint64, error) {
	return s.deltaRepository.GetHostTimeline(ctx, ip, limit, offset)
}

// GetScanEvents returns paginated change events for one scan.
func (s *Service) GetScanEvents(
	ctx context.Context,
	scanID, limit, offset uint64,
) ([]*deltarepository.ChangeEvent, uint64, error) {
	return s.deltaRepository.GetScanEvents(ctx, scanID, limit, offset)
}

// StreamChangeEvents passes each change event of one scan to fn in newest-
// first order. The handler uses this to write CSV directly to the wire so
// large delta sets don't materialise in memory.
func (s *Service) StreamChangeEvents(ctx context.Context, scanID uint64, fn func(*deltarepository.ChangeEvent) error) error {
	return s.deltaRepository.StreamChangeEvents(ctx, scanID, fn)
}
