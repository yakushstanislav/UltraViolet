// Package summary produces the dashboard overview counters and the
// scan-history summary (duration / success rate / recent scans).
package summary

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	dashboarddto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/dashboard"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/nullable"
	cvematch "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/alert"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/delta"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/savedsearch"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
)

const (
	recentScansLimit uint64 = 10
	topCVELimit      uint64 = 10
	successWindow           = 7 * 24 * time.Hour
)

// Service answers the dashboard overview endpoints.
type Service struct {
	hosts         host.Repository
	services      service.Repository
	scans         scan.Repository
	savedSearches savedsearch.Repository
	deltas        delta.Repository
	alerts        alert.Repository
	cveMatches    cvematch.Repository
}

// New builds a Service with the read-only repositories it needs.
func New(
	hosts host.Repository,
	services service.Repository,
	scans scan.Repository,
	savedSearches savedsearch.Repository,
	deltas delta.Repository,
	alerts alert.Repository,
	cveMatches cvematch.Repository,
) *Service {
	return &Service{
		hosts:         hosts,
		services:      services,
		scans:         scans,
		savedSearches: savedSearches,
		deltas:        deltas,
		alerts:        alerts,
		cveMatches:    cveMatches,
	}
}

// Compute fans out the overview counters in parallel and folds the results
// into the dashboard summary DTO.
func (s *Service) Compute(ctx context.Context, now time.Time) (dashboarddto.Response, error) {
	since24h := now.Add(-24 * time.Hour)
	since7d := now.Add(-7 * 24 * time.Hour)
	since30d := now.Add(-30 * 24 * time.Hour)

	out := dashboarddto.Response{}

	var (
		lastFinished    time.Time
		lastFinishedSet bool
		cveCounts       cvematch.SeverityCounts
		cveHostsCrit    uint64
		topCVEs         []cvematch.TopCVE
	)

	tasks := []countTask{
		{&out.Hosts, func(ctx context.Context) (uint64, error) { return s.hosts.Count(ctx) }},
		{&out.Services, func(ctx context.Context) (uint64, error) { return s.services.Count(ctx) }},
		{&out.Scans24h, countSince(s.scans, since24h)},
		{&out.Scans7d, countSince(s.scans, since7d)},
		{&out.Scans30d, countSince(s.scans, since30d)},
		{&out.AlertsActive, func(ctx context.Context) (uint64, error) { return s.alerts.CountActiveRules(ctx) }},
		{&out.AlertsFired24h, func(ctx context.Context) (uint64, error) { return s.alerts.CountEventsSince(ctx, since24h) }},
		{&out.SavedSearches, func(ctx context.Context) (uint64, error) { return s.savedSearches.Count(ctx) }},
	}

	group, groupCtx := errgroup.WithContext(ctx)

	for _, task := range tasks {
		group.Go(task.run(groupCtx))
	}

	group.Go(func() error {
		totals, err := s.scans.CountStatusTotals(groupCtx)
		if err != nil {
			return err
		}

		out.Pending = totals.Pending
		out.Running = totals.Running
		out.Paused = totals.Paused
		out.Done = totals.Done
		out.Failed = totals.Failed

		return nil
	})

	group.Go(func() error {
		changes, err := s.deltas.CountChangesByKindSince(groupCtx, since7d)
		if err != nil {
			return err
		}

		out.ChangeEvents7dNew = changes.New
		out.ChangeEvents7dDisappeared = changes.Disappeared
		out.ChangeEvents7dChanged = changes.Changed

		return nil
	})

	group.Go(func() error {
		last, err := s.scans.LastFinishedAt(groupCtx)
		if err != nil {
			return err
		}

		if last.Valid {
			lastFinished = last.Time.UTC()
			lastFinishedSet = true
		}

		return nil
	})

	if s.cveMatches != nil {
		group.Go(func() error {
			counts, err := s.cveMatches.GlobalCounts(groupCtx)
			if err != nil {
				return err
			}

			cveCounts = counts

			return nil
		})

		group.Go(func() error {
			n, err := s.cveMatches.HostsWithSeverityAtLeast(groupCtx, "CRITICAL")
			if err != nil {
				return err
			}

			cveHostsCrit = n

			return nil
		})

		group.Go(func() error {
			rows, err := s.cveMatches.TopCVEs(groupCtx, topCVELimit)
			if err != nil {
				return err
			}

			topCVEs = rows

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return dashboarddto.Response{}, err
	}

	if lastFinishedSet {
		out.LastScanFinishedAt = lastFinished.Format(time.RFC3339)
	}

	out.HostsWithCriticalCVE = cveHostsCrit
	out.CVECritical = cveCounts.Critical
	out.CVEHigh = cveCounts.High
	out.CVEMedium = cveCounts.Medium
	out.CVELow = cveCounts.Low

	if len(topCVEs) > 0 {
		out.TopCVEs = make([]dashboarddto.TopCVE, 0, len(topCVEs))

		for _, row := range topCVEs {
			entry := dashboarddto.TopCVE{ID: row.CVEID, Services: row.Services}

			if row.Severity.Valid {
				entry.Severity = row.Severity.String
			}

			if row.Score.Valid {
				score := row.Score.Float64
				entry.Score = &score
			}

			if row.Summary.Valid {
				entry.Summary = row.Summary.String
			}

			out.TopCVEs = append(out.TopCVEs, entry)
		}
	}

	return out, nil
}

// Scans aggregates scan duration, success rate, and recently-terminated scans.
func (s *Service) Scans(ctx context.Context, now time.Time) (dashboarddto.ScansResponse, error) {
	since := now.Add(-successWindow)

	var (
		duration scan.DurationStats
		success  scan.SuccessStats
		recent   []scan.RecentScan
	)

	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		out, err := s.scans.DurationStats(groupCtx)
		if err != nil {
			return err
		}

		duration = out

		return nil
	})

	group.Go(func() error {
		out, err := s.scans.SuccessStatsSince(groupCtx, since)
		if err != nil {
			return err
		}

		success = out

		return nil
	})

	group.Go(func() error {
		out, err := s.scans.RecentWithDelta(groupCtx, recentScansLimit)
		if err != nil {
			return err
		}

		recent = out

		return nil
	})

	if err := group.Wait(); err != nil {
		return dashboarddto.ScansResponse{}, err
	}

	return buildScansResponse(duration, success, recent), nil
}

// countTask binds an output counter to the function that fills it.
type countTask struct {
	dst *uint64
	fn  func(ctx context.Context) (uint64, error)
}

// run returns an errgroup-ready closure that captures ctx for one task.
func (t countTask) run(ctx context.Context) func() error {
	return func() error {
		n, err := t.fn(ctx)
		if err != nil {
			return err
		}

		*t.dst = n

		return nil
	}
}

func countSince(repository scan.Repository, since time.Time) func(context.Context) (uint64, error) {
	return func(ctx context.Context) (uint64, error) {
		return repository.CountSince(ctx, since)
	}
}

func buildScansResponse(duration scan.DurationStats, success scan.SuccessStats, recent []scan.RecentScan) dashboarddto.ScansResponse {
	out := dashboarddto.ScansResponse{
		Recent: make([]dashboarddto.RecentScan, 0, len(recent)),
	}

	if duration.Sample > 0 {
		avg := duration.AvgSec
		median := duration.MedianSec
		out.AvgDurationSec = &avg
		out.MedianDurationSec = &median
	}

	if total := success.Done + success.Failed; total > 0 {
		rate := float64(success.Done) / float64(total)
		out.SuccessRate7d = &rate
	}

	for _, row := range recent {
		out.Recent = append(out.Recent, recentScanToDTO(row))
	}

	return out
}

func recentScanToDTO(row scan.RecentScan) dashboarddto.RecentScan {
	dto := dashboarddto.RecentScan{
		ScanID:              row.ID,
		Status:              string(row.Status),
		ServicesFound:       row.ServicesFound,
		NewServices:         row.NewServices,
		DisappearedServices: row.DisappearedServices,
		ChangedServices:     row.ChangedServices,
		Name:                nullable.String(row.Name),
		FinishedAt:          nullable.TimeRFC3339(row.FinishedAt),
	}

	if row.StartedAt.Valid && row.FinishedAt.Valid {
		dur := int64(row.FinishedAt.Time.Sub(row.StartedAt.Time).Seconds())
		if dur < 0 {
			dur = 0
		}

		dto.DurationSec = &dur
	}

	return dto
}
