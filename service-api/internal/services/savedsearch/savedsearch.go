// Package savedsearch manages named search queries.
package savedsearch

import (
	"context"

	savedsearchrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/savedsearch"
)

// Service wraps saved-search persistence for the HTTP API.
type Service struct {
	savedSearchRepository savedsearchrepository.Repository
}

// NewService builds a Service.
func NewService(savedSearchRepository savedsearchrepository.Repository) *Service {
	return &Service{savedSearchRepository: savedSearchRepository}
}

// Create inserts a saved search and returns its id.
func (s *Service) Create(ctx context.Context, name string, query map[string]any) (uint64, error) {
	return s.savedSearchRepository.Create(ctx, name, query)
}

// GetAll lists saved searches with pagination.
func (s *Service) GetAll(
	ctx context.Context,
	limit, offset uint64,
) ([]*savedsearchrepository.SavedSearch, uint64, error) {
	return s.savedSearchRepository.GetAll(ctx, limit, offset)
}

// Delete removes a saved search by id.
func (s *Service) Delete(ctx context.Context, id uint64) error {
	return s.savedSearchRepository.Delete(ctx, id)
}

// Get loads one saved search by id.
func (s *Service) Get(ctx context.Context, id uint64) (*savedsearchrepository.SavedSearch, error) {
	return s.savedSearchRepository.Get(ctx, id)
}

// MarkRun records that a saved search was executed.
func (s *Service) MarkRun(ctx context.Context, id uint64) error {
	return s.savedSearchRepository.MarkRun(ctx, id)
}
