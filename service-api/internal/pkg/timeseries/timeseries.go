// Package timeseries provides shared time-bucket utilities for dashboard trends.
package timeseries

import (
	"fmt"
	"time"
)

// Bucket is the granularity of a time-series aggregation.
type Bucket string

const (
	// BucketHour aggregates points by UTC hour.
	BucketHour Bucket = "hour"
	// BucketDay aggregates points by UTC day.
	BucketDay Bucket = "day"
)

// Truncate snaps t down to the bucket boundary in UTC.
func (b Bucket) Truncate(t time.Time) time.Time {
	utc := t.UTC()

	switch b {
	case BucketHour:
		return time.Date(utc.Year(), utc.Month(), utc.Day(), utc.Hour(), 0, 0, 0, time.UTC)
	case BucketDay:
		return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	}

	return utc
}

// Step returns the duration of one bucket.
func (b Bucket) Step() time.Duration {
	switch b {
	case BucketHour:
		return time.Hour
	case BucketDay:
		return 24 * time.Hour
	}

	return 0
}

// Series returns bucket boundaries from `since` (truncated) up to and including
// the bucket that contains `until`. Boundaries are returned in chronological
// order in UTC.
func Series(since, until time.Time, b Bucket) []time.Time {
	step := b.Step()
	if step == 0 {
		return nil
	}

	start := b.Truncate(since)
	end := b.Truncate(until)

	if end.Before(start) {
		return nil
	}

	out := make([]time.Time, 0, int(end.Sub(start)/step)+1)
	for ts := start; !ts.After(end); ts = ts.Add(step) {
		out = append(out, ts)
	}

	return out
}

// BucketRows is the minimal SQL rows shape consumed by ReadBucketMap. Both
// pgx.Rows and *sql.Rows satisfy it; declaring it locally keeps this package
// free of a driver dependency.
type BucketRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// ReadBucketMap drains rows of the shape (bucket time.Time, count bigint)
// into a map keyed by the UTC bucket boundary. Negative counts (which can
// happen with int64 overflow guards) are clamped to zero. The caller still
// owns rows and must Close them.
func ReadBucketMap(rows BucketRows) (map[time.Time]uint64, error) {
	out := make(map[time.Time]uint64)

	for rows.Next() {
		var (
			ts time.Time
			n  int64
		)

		if err := rows.Scan(&ts, &n); err != nil {
			return nil, fmt.Errorf("scan bucket row: %w", err)
		}

		if n < 0 {
			n = 0
		}

		out[ts.UTC()] = uint64(n)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate bucket rows: %w", err)
	}

	return out, nil
}
