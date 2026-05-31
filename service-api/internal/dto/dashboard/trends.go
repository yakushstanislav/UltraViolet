package dashboard

import (
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// TrendsRequest is the validated query string for GET /v1/dashboard/trends.
type TrendsRequest struct {
	Range  string `validate:"required,oneof=24h 7d 30d"`
	Bucket string `validate:"required,oneof=hour day"`
}

// IsValid runs struct validation on the parsed query.
func (r *TrendsRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate dashboard trends request: %w", err)
	}

	return nil
}

// TrendsPoint is one bucket of the trends time-series.
type TrendsPoint struct {
	TS                string `json:"ts"`
	ScansCreated      uint64 `json:"scans_created"`
	ScansCompleted    uint64 `json:"scans_completed"`
	HostsDiscovered   uint64 `json:"hosts_discovered"`
	ChangeNew         uint64 `json:"change_new"`
	ChangeDisappeared uint64 `json:"change_disappeared"`
	ChangeChanged     uint64 `json:"change_changed"`
}

// TrendsResponse is the wire format of GET /v1/dashboard/trends.
type TrendsResponse struct {
	Range  string        `json:"range"`
	Bucket string        `json:"bucket"`
	Points []TrendsPoint `json:"points"`
}
