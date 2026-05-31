// Package trends produces the bucketed time-series the dashboard shows for
// scans, host discovery, and change events.
package trends

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	dashboarddto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/dashboard"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/timeseries"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/delta"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
)

// Service answers GET /dashboard/trends.
type Service struct {
	scans  scan.Repository
	hosts  host.Repository
	deltas delta.Repository
}

// New builds a Service with the three repositories it needs.
func New(scans scan.Repository, hosts host.Repository, deltas delta.Repository) *Service {
	return &Service{scans: scans, hosts: hosts, deltas: deltas}
}

// Compute returns the time-series for the requested range and bucket.
// `bucket` must already be a valid timeseries.Bucket string.
func (s *Service) Compute(ctx context.Context, now time.Time, rng, bucket string) (dashboarddto.TrendsResponse, error) {
	bucketGran := timeseries.Bucket(bucket)
	since := bucketGran.Truncate(rangeStart(now, rng))

	var (
		created       map[time.Time]uint64
		completed     map[time.Time]uint64
		discovered    map[time.Time]uint64
		changeNew     map[time.Time]uint64
		changeGone    map[time.Time]uint64
		changeChanged map[time.Time]uint64
	)

	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		out, err := s.scans.BucketedCreatedSince(groupCtx, since, bucket)
		if err != nil {
			return err
		}

		created = out

		return nil
	})

	group.Go(func() error {
		out, err := s.scans.BucketedCompletedSince(groupCtx, since, bucket)
		if err != nil {
			return err
		}

		completed = out

		return nil
	})

	group.Go(func() error {
		out, err := s.hosts.BucketedFirstSeenSince(groupCtx, since, bucket)
		if err != nil {
			return err
		}

		discovered = out

		return nil
	})

	group.Go(func() error {
		out, err := s.deltas.BucketedChangesSince(groupCtx, since, bucket, delta.ChangeKindNew)
		if err != nil {
			return err
		}

		changeNew = out

		return nil
	})

	group.Go(func() error {
		out, err := s.deltas.BucketedChangesSince(groupCtx, since, bucket, delta.ChangeKindDisappeared)
		if err != nil {
			return err
		}

		changeGone = out

		return nil
	})

	group.Go(func() error {
		out, err := s.deltas.BucketedChangesSince(groupCtx, since, bucket, delta.ChangeKindChanged)
		if err != nil {
			return err
		}

		changeChanged = out

		return nil
	})

	if err := group.Wait(); err != nil {
		return dashboarddto.TrendsResponse{}, err
	}

	boundaries := timeseries.Series(since, now, bucketGran)
	points := make([]dashboarddto.TrendsPoint, 0, len(boundaries))

	for _, ts := range boundaries {
		points = append(points, dashboarddto.TrendsPoint{
			TS:                ts.Format(time.RFC3339),
			ScansCreated:      created[ts],
			ScansCompleted:    completed[ts],
			HostsDiscovered:   discovered[ts],
			ChangeNew:         changeNew[ts],
			ChangeDisappeared: changeGone[ts],
			ChangeChanged:     changeChanged[ts],
		})
	}

	return dashboarddto.TrendsResponse{
		Range:  rng,
		Bucket: bucket,
		Points: points,
	}, nil
}

// DefaultBucketForRange picks the bucket granularity that matches the trend window.
func DefaultBucketForRange(rng string) string {
	if rng == "24h" {
		return string(timeseries.BucketHour)
	}

	return string(timeseries.BucketDay)
}

// rangeStart maps the wire range string to its origin time.
func rangeStart(now time.Time, rng string) time.Time {
	switch rng {
	case "24h":
		return now.Add(-24 * time.Hour)
	case "7d":
		return now.Add(-7 * 24 * time.Hour)
	case "30d":
		return now.Add(-30 * 24 * time.Hour)
	}

	return now.Add(-7 * 24 * time.Hour)
}
