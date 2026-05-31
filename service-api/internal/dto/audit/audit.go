package audit

import (
	"errors"
	"fmt"
	"time"

	auditrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/audit"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// Event is the wire shape returned by GET /v1/audit.
type Event struct {
	ID         uint64  `json:"id"`
	UserID     *uint64 `json:"user_id,omitempty"`
	ActorRole  string  `json:"actor_role,omitempty"`
	ActorIP    string  `json:"actor_ip,omitempty"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	StatusCode int     `json:"status_code"`
	ResourceID string  `json:"resource_id,omitempty"`
	UserAgent  string  `json:"user_agent,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

// NewEventResponse converts a repository row into a wire DTO.
func NewEventResponse(item *auditrepository.Event) *Event {
	if item == nil {
		return nil
	}

	out := &Event{
		ID:         item.ID,
		Method:     item.Method,
		Path:       item.Path,
		StatusCode: item.StatusCode,
		CreatedAt:  item.CreatedAt.UTC().Format(time.RFC3339),
	}

	if item.UserID.Valid && item.UserID.Int64 > 0 {
		userID := uint64(item.UserID.Int64)
		out.UserID = &userID
	}

	if item.ActorRole.Valid {
		out.ActorRole = item.ActorRole.String
	}

	if item.ActorIP.Valid {
		out.ActorIP = item.ActorIP.String
	}

	if item.ResourceID.Valid {
		out.ResourceID = item.ResourceID.String
	}

	if item.UserAgent.Valid {
		out.UserAgent = item.UserAgent.String
	}

	return out
}

// ListParams is the validated set of query-string filters accepted by
// GET /v1/audit. All fields are optional and an empty struct means
// "no filtering".
type ListParams struct {
	Method       string  `validate:"omitempty,oneof=GET POST PUT PATCH DELETE HEAD OPTIONS"`
	StatusFamily string  `validate:"omitempty,oneof=2xx 3xx 4xx 5xx"`
	Query        string  `validate:"omitempty,max=200,noctrl"`
	UserID       *uint64 `validate:"omitempty,gt=0"`
	Since        *time.Time
	Until        *time.Time
}

// IsValid runs struct-level validation against the configured rules.
func (p *ListParams) IsValid() error {
	if err := validate.Struct(p); err != nil {
		return fmt.Errorf("can't validate audit list params: %w", err)
	}

	if p.Since != nil && p.Until != nil && !p.Since.Before(*p.Until) {
		return errors.New("since must be earlier than until")
	}

	return nil
}

// ToRepositoryFilter maps the DTO into the repository-layer filter struct.
func (p *ListParams) ToRepositoryFilter() auditrepository.ListFilter {
	return auditrepository.ListFilter{
		Method:       p.Method,
		StatusFamily: p.StatusFamily,
		Query:        p.Query,
		UserID:       p.UserID,
		Since:        p.Since,
		Until:        p.Until,
	}
}
