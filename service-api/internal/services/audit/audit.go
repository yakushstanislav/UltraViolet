// Package audit lists persisted request audit events.
package audit

import (
	"context"

	auditrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/audit"
)

// Service wraps audit persistence for the HTTP API and audit middleware.
type Service struct {
	auditRepository auditrepository.Repository
}

// NewService builds a Service.
func NewService(auditRepository auditrepository.Repository) *Service {
	return &Service{auditRepository: auditRepository}
}

// Repository exposes the underlying store for audit middleware inserts.
func (s *Service) Repository() auditrepository.Repository {
	return s.auditRepository
}

// List returns a page of audit events that match filter.
func (s *Service) List(
	ctx context.Context,
	filter auditrepository.ListFilter,
	limit, offset uint64,
) ([]*auditrepository.Event, uint64, error) {
	return s.auditRepository.List(ctx, filter, limit, offset)
}
