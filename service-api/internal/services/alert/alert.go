// Package alert manages alert rules and firing events.
package alert

import (
	"context"

	alertrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/alert"
)

// Service wraps alert persistence for the HTTP API.
type Service struct {
	alertRepository alertrepository.Repository
}

// NewService builds a Service.
func NewService(alertRepository alertrepository.Repository) *Service {
	return &Service{alertRepository: alertRepository}
}

// CreateRule inserts a new alert rule.
func (s *Service) CreateRule(ctx context.Context, input *alertrepository.Rule) (uint64, error) {
	return s.alertRepository.CreateRule(ctx, input)
}

// GetRules returns enabled rules with pagination.
func (s *Service) GetRules(ctx context.Context, limit, offset uint64) ([]*alertrepository.Rule, uint64, error) {
	return s.alertRepository.GetRules(ctx, limit, offset)
}

// GetAllRules returns every rule with pagination.
func (s *Service) GetAllRules(ctx context.Context, limit, offset uint64) ([]*alertrepository.Rule, uint64, error) {
	return s.alertRepository.GetAllRules(ctx, limit, offset)
}

// DeleteRule removes a rule by id.
func (s *Service) DeleteRule(ctx context.Context, id uint64) error {
	return s.alertRepository.DeleteRule(ctx, id)
}

// SetRuleEnabled toggles a rule.
func (s *Service) SetRuleEnabled(ctx context.Context, id uint64, enabled bool) error {
	return s.alertRepository.SetRuleEnabled(ctx, id, enabled)
}

// GetEvents returns alert firing events with pagination.
func (s *Service) GetEvents(ctx context.Context, limit, offset uint64) ([]*alertrepository.Event, uint64, error) {
	return s.alertRepository.GetEvents(ctx, limit, offset)
}
