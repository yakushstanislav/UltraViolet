package cve

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	cvedto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/cve"
	cvecatalog "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/catalog"
	cvematch "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	cvesyncstate "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/syncstate"
)

// Service answers /v1/services/{id}/cves, /v1/cves/{id}, and CVE sync status.
type Service struct {
	catalog       cvecatalog.Repository
	matches       cvematch.Repository
	syncState     cvesyncstate.Repository
	bootstrapFrom time.Duration
}

// New builds a Service.
func New(
	catalog cvecatalog.Repository,
	matches cvematch.Repository,
	syncState cvesyncstate.Repository,
	cfg Config,
) *Service {
	return &Service{
		catalog:       catalog,
		matches:       matches,
		syncState:     syncState,
		bootstrapFrom: cfg.SyncBootstrapFrom,
	}
}

// ListForService returns the CVEs matched against a service.
func (s *Service) ListForService(ctx context.Context, serviceID uint64) ([]cvedto.ServiceCVE, error) {
	groups, err := s.matches.ListByServiceIDs(ctx, []uint64{serviceID})
	if err != nil {
		return nil, fmt.Errorf("can't list service cves: %w", err)
	}

	rows := groups[serviceID]
	out := make([]cvedto.ServiceCVE, 0, len(rows))

	for _, row := range rows {
		entry := cvedto.ServiceCVE{
			ID:        row.CVEID,
			MatchedAt: row.MatchedAt.Format(time.RFC3339),
		}

		if row.Severity.Valid {
			entry.Severity = row.Severity.String
		}

		if row.CVSSScore.Valid {
			score := row.CVSSScore.Float64
			entry.CVSSScore = &score
		}

		if row.Summary.Valid {
			entry.Summary = row.Summary.String
		}

		if row.MatchedVersion.Valid {
			entry.MatchedVersion = row.MatchedVersion.String
		}

		if row.Confidence > 0 {
			conf := int(row.Confidence)
			entry.Confidence = &conf
		}

		out = append(out, entry)
	}

	return out, nil
}

// GetByID returns one CVE by id.
func (s *Service) GetByID(ctx context.Context, id string) (cvedto.CVE, error) {
	row, err := s.catalog.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, cvecatalog.ErrNotFound) {
			return cvedto.CVE{}, ErrNotFound
		}

		return cvedto.CVE{}, fmt.Errorf("can't load cve: %w", err)
	}

	out := cvedto.CVE{
		ID:         row.ID,
		Source:     row.Source,
		References: row.References,
	}

	if row.Summary.Valid {
		out.Summary = row.Summary.String
	}

	if row.CVSSv3Score.Valid {
		score := row.CVSSv3Score.Float64
		out.CVSSScore = &score
	}

	if row.CVSSv3Severity.Valid {
		out.CVSSSeverity = row.CVSSv3Severity.String
	}

	if row.CVSSv3Vector.Valid {
		out.CVSSVector = row.CVSSv3Vector.String
	}

	if row.PublishedAt.Valid {
		out.PublishedAt = row.PublishedAt.Time.Format(time.RFC3339)
	}

	if row.LastModifiedAt.Valid {
		out.LastModifiedAt = row.LastModifiedAt.Time.Format(time.RFC3339)
	}

	return out, nil
}

// SyncStatus reports whether the scanner finished the NVD bootstrap and, while
// it is still running, the progress fraction.
//
// Preferred metric is count-based: entries_done / entries_total persisted by
// cvesync. If those aren't populated yet (cold-start before the first window
// completes), the bar falls back to the time-window approximation against
// CVE_SYNC_BOOTSTRAP_FROM (kept in parity with uv-scanner's value).
func (s *Service) SyncStatus(ctx context.Context) (cvedto.SyncStatus, error) {
	state, err := s.syncState.Get(ctx)
	if err != nil {
		return cvedto.SyncStatus{}, fmt.Errorf("can't read cve sync state: %w", err)
	}

	out := cvedto.SyncStatus{Bootstrapped: state.BootstrappedAt.Valid}

	if state.EntriesDone.Valid {
		done := int(state.EntriesDone.Int32)
		out.EntriesDone = &done
	}

	if state.EntriesTotal.Valid {
		total := int(state.EntriesTotal.Int32)
		out.EntriesTotal = &total
	}

	if out.Bootstrapped {
		return out, nil
	}

	if state.EntriesTotal.Valid && state.EntriesTotal.Int32 > 0 && state.EntriesDone.Valid {
		ratio := float64(state.EntriesDone.Int32) / float64(state.EntriesTotal.Int32)
		if ratio > 1 {
			ratio = 1
		}

		out.Progress = &ratio

		return out, nil
	}

	now := time.Now().UTC()
	windowStart := now.Add(-s.effectiveBootstrapFrom())
	progress := bootstrapProgress(now, windowStart, state.LastModStart)
	out.Progress = &progress

	return out, nil
}

func (s *Service) effectiveBootstrapFrom() time.Duration {
	if s.bootstrapFrom > 0 {
		return s.bootstrapFrom
	}

	return 8760 * time.Hour
}

func bootstrapProgress(now, windowStart time.Time, last sql.NullTime) float64 {
	if !windowStart.Before(now) {
		return 0
	}

	span := now.Sub(windowStart)
	if span <= 0 {
		return 0
	}

	checkpoint := windowStart

	if last.Valid {
		checkpoint = last.Time.UTC()
	}

	covered := checkpoint.Sub(windowStart)
	if covered < 0 {
		covered = 0
	}

	if covered >= span {
		return 1
	}

	return float64(covered) / float64(span)
}

// ErrNotFound is returned when a CVE lookup misses.
var ErrNotFound = errors.New("cve not found")
