package feature

import (
	"fmt"
	"time"

	alertrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/alert"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// CreateAlertRequest is the payload accepted by POST /v1/alerts.
type CreateAlertRequest struct {
	Name        string         `json:"name" validate:"required,max=256"`
	Q           string         `json:"q" validate:"omitempty,max=2048"`
	Channel     string         `json:"channel" validate:"omitempty,max=64"`
	Destination string         `json:"destination" validate:"omitempty,max=512"`
	CooldownSec int32          `json:"cooldown_sec" validate:"omitempty,gt=0"`
	Query       map[string]any `json:"query"`
}

// IsValid validates alert creation request.
func (r CreateAlertRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate create alert request: %w", err)
	}

	return nil
}

// SetAlertEnabledRequest is the payload accepted by PATCH /v1/alerts/{id}/enabled.
type SetAlertEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

// IsValid validates the set-enabled request.
func (r SetAlertEnabledRequest) IsValid() error {
	return nil
}

// AlertRuleResponse is the wire shape returned by GET /v1/alerts*.
// Repository structs intentionally have no JSON tags, so handlers map
// them to this DTO before serialising.
type AlertRuleResponse struct {
	ID            uint64         `json:"id"`
	Name          string         `json:"name"`
	SavedSearchID *uint64        `json:"saved_search_id,omitempty"`
	Query         map[string]any `json:"query"`
	Channel       string         `json:"channel"`
	Destination   string         `json:"destination,omitempty"`
	CooldownSec   int32          `json:"cooldown_sec"`
	Enabled       bool           `json:"enabled"`
	LastFiredAt   *time.Time     `json:"last_fired_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// NewAlertRuleResponse converts a repository row into a wire DTO.
func NewAlertRuleResponse(item *alertrepository.Rule) *AlertRuleResponse {
	if item == nil {
		return nil
	}

	query := item.Query
	if query == nil {
		query = map[string]any{}
	}

	out := &AlertRuleResponse{
		ID:          item.ID,
		Name:        item.Name,
		Query:       query,
		Channel:     item.Channel,
		Destination: item.Destination,
		CooldownSec: item.CooldownSec,
		Enabled:     item.Enabled,
		CreatedAt:   item.CreatedAt,
		UpdatedAt:   item.UpdatedAt,
	}

	if item.SavedSearchID.Valid {
		savedSearchID := uint64(item.SavedSearchID.Int64)
		out.SavedSearchID = &savedSearchID
	}

	if item.LastFiredAt.Valid {
		lastFired := item.LastFiredAt.Time
		out.LastFiredAt = &lastFired
	}

	return out
}

// AlertEventResponse is the wire shape returned by GET /v1/alerts/events.
type AlertEventResponse struct {
	ID        uint64         `json:"id"`
	RuleID    uint64         `json:"rule_id"`
	HitsCount int            `json:"hits_count"`
	Payload   map[string]any `json:"payload,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// NewAlertEventResponse converts a repository row into a wire DTO.
func NewAlertEventResponse(item *alertrepository.Event) *AlertEventResponse {
	if item == nil {
		return nil
	}

	return &AlertEventResponse{
		ID:        item.ID,
		RuleID:    item.RuleID,
		HitsCount: item.HitsCount,
		Payload:   item.Payload,
		CreatedAt: item.CreatedAt,
	}
}
