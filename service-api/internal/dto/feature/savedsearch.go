package feature

import (
	"fmt"
	"time"

	savedsearchrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/savedsearch"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// CreateSavedSearchRequest is the payload accepted by POST /v1/saved-searches.
type CreateSavedSearchRequest struct {
	Name  string         `json:"name" validate:"required,max=256"`
	Query map[string]any `json:"query"`
}

// IsValid validates saved search creation request.
func (r CreateSavedSearchRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate create saved search request: %w", err)
	}

	return nil
}

// SavedSearchResponse is the wire shape returned by GET /v1/saved-searches.
// Repository structs intentionally have no JSON tags, so the handler maps
// them to this DTO before serialising.
type SavedSearchResponse struct {
	ID        uint64         `json:"id"`
	Name      string         `json:"name"`
	Query     map[string]any `json:"query"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	LastRunAt *time.Time     `json:"last_run_at,omitempty"`
}

// NewSavedSearchResponse converts a repository row into a wire DTO.
func NewSavedSearchResponse(item *savedsearchrepository.SavedSearch) *SavedSearchResponse {
	if item == nil {
		return nil
	}

	out := &SavedSearchResponse{
		ID:        item.ID,
		Name:      item.Name,
		Query:     item.Query,
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	}

	if item.LastRunAt.Valid {
		lastRun := item.LastRunAt.Time
		out.LastRunAt = &lastRun
	}

	return out
}
