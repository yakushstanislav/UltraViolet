// Package scan stores scan jobs and acts as the worker queue.
//
// The package is split across three files by concern:
//   - scan.go   — types, Repository contract, and CRUD operations
//   - state.go  — queue state machine (Claim, RecoverStaleRunning, …)
//   - stats.go  — read-only aggregates used by the dashboard
package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	scandto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/scan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmode"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanprofile"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/targetstrategy"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Status is the lifecycle state of a scan job.
type Status string

const (
	// StatusPending is a job that has been submitted but not yet picked up.
	StatusPending Status = "PENDING"
	// StatusRunning is a job currently being executed by a worker.
	StatusRunning Status = "RUNNING"
	// StatusDone is a job that has completed successfully.
	StatusDone Status = "DONE"
	// StatusFailed is a job that finished with an error.
	StatusFailed Status = "FAILED"
	// StatusCanceled is a job that was stopped by an operator before completion.
	StatusCanceled Status = "CANCELED"
	// StatusPaused is a job whose execution was interrupted (by user or by a
	// worker shutdown) and which will be resumed by the next available worker.
	StatusPaused Status = "PAUSED"
)

// CancelReasonByUser is the canonical error message stored when a scan is
// cancelled via the API.
const CancelReasonByUser = "scan cancelled by user"

// PauseReasonByUser is the canonical error message stored when a scan is
// paused via the API.
const PauseReasonByUser = "scan paused by user"

// PauseReasonInterrupted is the message stored when a RUNNING scan is
// reclaimed after a worker interruption (shutdown, kill, lost listener).
const PauseReasonInterrupted = "scan interrupted, will be resumed"

// ErrNotFound is returned when a scan lookup misses.
var ErrNotFound = pgkit.ErrNoRows

// ErrNoPendingScan is returned by Claim when the queue is empty.
var ErrNoPendingScan = errors.New("no pending scan")

// ErrNotCancelable is returned by RequestCancel when the scan is already in a
// terminal state (DONE/FAILED/CANCELED) and therefore cannot be cancelled.
var ErrNotCancelable = errors.New("scan is not in a cancelable state")

// ErrNotPauseable is returned by RequestPause when the scan is not in a state
// from which it can be paused (anything but RUNNING).
var ErrNotPauseable = errors.New("scan is not in a pauseable state")

// ErrNotResumable is returned by RequestResume when the scan is not paused
// and there is no pending pause request to cancel.
var ErrNotResumable = errors.New("scan is not in a resumable state")

// ErrNotRestartable is returned by Restart when the scan is in a state that
// the worker is actively driving (PENDING or RUNNING) and an in-place reset
// would race with the pipeline.
var ErrNotRestartable = errors.New("scan is not in a restartable state")

// Scan is a single scan job.
type Scan struct {
	ID              uint64
	Name            sql.NullString
	CIDR            sql.NullString
	Country         sql.NullString
	Ports           []int32
	PortsExpr       []scandto.PortExprItem
	Mode            string
	SlowProfile     string
	TargetStrategy  string
	HostLimit       sql.NullInt64
	Status          Status
	StartedAt       sql.NullTime
	FinishedAt      sql.NullTime
	Error           sql.NullString
	Stats           map[string]any
	StatsUpdatedAt  sql.NullTime
	CreatedAt       time.Time
	CancelRequested bool
	PauseRequested  bool
	// AutoResume marks a PAUSED scan as one that the worker should re-claim
	// on its next tick. It is true for scans paused by RecoverStaleRunning or
	// worker-shutdown finalisation, and for scans whose Resume was requested
	// by an operator. User-initiated pauses leave it false so the scan stays
	// paused until an explicit Resume.
	AutoResume bool
	// ProgressCursor lets a paused scan resume from where it left off instead
	// of restarting the whole CIDR. Interpretation is strategy-dependent (see
	// migration 4_scan_progress_cursor). Empty string means "start from the
	// beginning".
	ProgressCursor string
	ScheduleID     sql.NullInt64
}

// DurationStats holds aggregate duration metrics across DONE scans with both
// started_at and finished_at populated.
type DurationStats struct {
	AvgSec    float64
	MedianSec float64
	Sample    uint64
}

// SuccessStats holds raw DONE / FAILED counts over a window.
type SuccessStats struct {
	Done   uint64
	Failed uint64
}

// RecentScan is a terminal-state scan annotated with its delta summary and
// the number of services snapshotted for it.
type RecentScan struct {
	ID                  uint64
	Name                sql.NullString
	Status              Status
	StartedAt           sql.NullTime
	FinishedAt          sql.NullTime
	NewServices         int32
	DisappearedServices int32
	ChangedServices     int32
	ServicesFound       uint64
}

// Repository describes the scan storage contract.
type Repository interface {
	Create(ctx context.Context, scan *Scan) (uint64, error)
	GetByID(ctx context.Context, id uint64) (*Scan, error)
	GetAll(ctx context.Context, limit, offset uint64, sortColumn string, sortDesc bool) ([]*Scan, uint64, error)
	UpdateStatus(ctx context.Context, id uint64, status Status, errMsg string) error
	UpdateStats(ctx context.Context, id uint64, stats map[string]any) error
	Claim(ctx context.Context) (*Scan, error)
	RecoverStaleRunning(ctx context.Context, maxAge time.Duration) (uint64, error)
	ReclaimAllRunning(ctx context.Context) (uint64, error)
	CountByStatus(ctx context.Context, status Status) (uint64, error)
	CountStatusTotals(ctx context.Context) (StatusCounts, error)
	CountSince(ctx context.Context, since time.Time) (uint64, error)
	LastFinishedAt(ctx context.Context) (sql.NullTime, error)
	BucketedCreatedSince(ctx context.Context, since time.Time, bucket string) (map[time.Time]uint64, error)
	BucketedCompletedSince(ctx context.Context, since time.Time, bucket string) (map[time.Time]uint64, error)
	DurationStats(ctx context.Context) (DurationStats, error)
	SuccessStatsSince(ctx context.Context, since time.Time) (SuccessStats, error)
	RecentWithDelta(ctx context.Context, limit uint64) ([]RecentScan, error)
	RequestCancel(ctx context.Context, id uint64) (Status, error)
	IsCancelRequested(ctx context.Context, id uint64) (bool, error)
	MarkAbandonedCanceled(ctx context.Context) (uint64, error)
	RequestPause(ctx context.Context, id uint64) (Status, error)
	IsPauseRequested(ctx context.Context, id uint64) (bool, error)
	MarkPaused(ctx context.Context, id uint64, reason string, autoResume bool) error
	RequestResume(ctx context.Context, id uint64) (Status, error)
	UpdateProgressCursor(ctx context.Context, id uint64, cursor string) error
	Restart(ctx context.Context, id uint64) (Status, error)
	DistinctHostsScanned(ctx context.Context, scanID uint64) (uint64, error)
	RecentScannedHosts(ctx context.Context, scanID, limit uint64) ([]RecentScannedHost, error)
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL builds a new Repository backed by the given pool.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

// SortColumns is the canonical whitelist of sortable scan columns. It is
// exported so the handler layer can validate incoming `sort=...` query
// parameters against the same vocabulary used by the repository.
var SortColumns = map[string]struct{}{
	"id":         {},
	"created_at": {},
	"status":     {},
}

// IsValidSortColumn reports whether column may appear in ORDER BY.
func IsValidSortColumn(column string) bool {
	_, ok := SortColumns[column]

	return ok
}

// scanColumns is the canonical projection used by every Scan-returning query.
var scanColumns = []string{
	"id", "name", "cidr", "country", "ports", "ports_expr", "mode", "slow_profile", "target_strategy", "host_limit",
	"status", "started_at", "finished_at", "error", "stats", "stats_updated_at",
	"created_at", "cancel_requested", "pause_requested", "auto_resume", "progress_cursor", "schedule_id",
}

// Create persists a new scan job in PENDING state.
func (p *PostgreSQL) Create(ctx context.Context, scan *Scan) (uint64, error) {
	if scan.CreatedAt.IsZero() {
		scan.CreatedAt = time.Now().UTC()
	}

	if scan.Status == "" {
		scan.Status = StatusPending
	}

	if scan.Mode == "" {
		scan.Mode = string(scanmode.Slow)
	}

	if scan.SlowProfile == "" {
		scan.SlowProfile = string(scanprofile.Stealth)
	}

	if scan.TargetStrategy == "" {
		scan.TargetStrategy = string(targetstrategy.Sequential)
	}

	var portsExprArg any

	if len(scan.PortsExpr) > 0 {
		portsJSON, marshalErr := json.Marshal(scan.PortsExpr)
		if marshalErr != nil {
			return 0, fmt.Errorf("can't marshal ports expression: %w", marshalErr)
		}

		portsExprArg = portsJSON
	}

	columns := []string{
		"name", "cidr", "country", "ports", "ports_expr", "mode", "slow_profile", "target_strategy", "host_limit", "status", "created_at",
	}
	values := []any{
		scan.Name, scan.CIDR, scan.Country, scan.Ports, portsExprArg, scan.Mode, scan.SlowProfile, scan.TargetStrategy, scan.HostLimit, scan.Status, scan.CreatedAt,
	}

	if scan.ScheduleID.Valid {
		columns = append(columns, "schedule_id")
		values = append(values, scan.ScheduleID.Int64)
	}

	query, args, err := sq.Insert("uv_scan").
		Columns(columns...).
		Values(values...).
		Suffix("RETURNING id").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build create scan query: %w", err)
	}

	var id uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("can't create scan: %w", pgkit.Handle(err))
	}

	return id, nil
}

// GetByID returns a scan by its primary key.
func (p *PostgreSQL) GetByID(ctx context.Context, id uint64) (*Scan, error) {
	query, args, err := sq.Select(scanColumns...).From("uv_scan").Where(squirrel.Eq{"id": id}).ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get scan by id query: %w", err)
	}

	return scanRow(p.pool.QueryRow(ctx, query, args...))
}

// GetAll returns scans with limit/offset pagination and a fixed whitelist ORDER BY.
func (p *PostgreSQL) GetAll(ctx context.Context, limit, offset uint64, sortColumn string, sortDesc bool) ([]*Scan, uint64, error) {
	if limit == 0 {
		limit = 100
	}

	countQuery, countArgs, err := sq.Select("COUNT(*)").From("uv_scan").ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count scans query: %w", err)
	}

	var total uint64

	err = p.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("can't count scans: %w", pgkit.Handle(err))
	}

	orderCol := "id"
	if IsValidSortColumn(sortColumn) {
		orderCol = sortColumn
	}

	orderDir := "ASC"
	if sortDesc {
		orderDir = "DESC"
	}

	query, args, err := sq.Select(scanColumns...).
		From("uv_scan").
		OrderBy(orderCol + " " + orderDir).
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build get all scans query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't query scans: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var scans []*Scan

	for rows.Next() {
		s, err := scanRow(rows)
		if err != nil {
			return nil, 0, err
		}

		scans = append(scans, s)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate scans: %w", err)
	}

	return scans, total, nil
}

// UpdateStatus transitions a scan to the new status, recording start/finish times and any error.
func (p *PostgreSQL) UpdateStatus(ctx context.Context, id uint64, status Status, errMsg string) error {
	now := time.Now().UTC()

	var (
		startedAt  sql.NullTime
		finishedAt sql.NullTime
		errValue   sql.NullString
	)

	switch status {
	case StatusRunning:
		startedAt = sql.NullTime{Time: now, Valid: true}
	case StatusDone, StatusFailed, StatusCanceled:
		finishedAt = sql.NullTime{Time: now, Valid: true}
	}

	if errMsg != "" {
		errValue = sql.NullString{String: errMsg, Valid: true}
	}

	query, args, err := sq.Update("uv_scan").
		Set("status", status).
		Set("started_at", squirrel.Expr("COALESCE(started_at, ?)", startedAt)).
		Set("finished_at", squirrel.Expr("COALESCE(?, finished_at)", finishedAt)).
		Set("error", squirrel.Expr("COALESCE(?, error)", errValue)).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update scan status query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update scan status: %w", pgkit.Handle(err))
	}

	return nil
}

// UpdateProgressCursor stores the resume cursor for a scan. Empty cursor
// clears the column. Called frequently by the worker during a scan, so the
// query is intentionally minimal.
func (p *PostgreSQL) UpdateProgressCursor(ctx context.Context, id uint64, cursor string) error {
	query, args, err := sq.Update("uv_scan").
		Set("progress_cursor", cursor).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update progress cursor query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update progress cursor: %w", pgkit.Handle(err))
	}

	return nil
}

// UpdateStats overwrites the JSON stats blob.
func (p *PostgreSQL) UpdateStats(ctx context.Context, id uint64, stats map[string]any) error {
	statsJSON, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("can't marshal stats: %w", err)
	}

	query, args, err := sq.Update("uv_scan").
		Set("stats", statsJSON).
		Set("stats_updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update scan stats query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't update scan stats: %w", pgkit.Handle(err))
	}

	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

// scanRow projects one uv_scan row (using scanColumns order) into a *Scan,
// unmarshalling the JSON columns along the way.
func scanRow(row rowScanner) (*Scan, error) {
	var (
		s             Scan
		statsJSON     []byte
		portsExprJSON []byte
	)

	err := row.Scan(
		&s.ID,
		&s.Name,
		&s.CIDR,
		&s.Country,
		&s.Ports,
		&portsExprJSON,
		&s.Mode,
		&s.SlowProfile,
		&s.TargetStrategy,
		&s.HostLimit,
		&s.Status,
		&s.StartedAt,
		&s.FinishedAt,
		&s.Error,
		&statsJSON,
		&s.StatsUpdatedAt,
		&s.CreatedAt,
		&s.CancelRequested,
		&s.PauseRequested,
		&s.AutoResume,
		&s.ProgressCursor,
		&s.ScheduleID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgkit.ErrNoRows
		}

		return nil, fmt.Errorf("can't scan scan row: %w", pgkit.Handle(err))
	}

	if len(portsExprJSON) > 0 {
		if err := json.Unmarshal(portsExprJSON, &s.PortsExpr); err != nil {
			return nil, fmt.Errorf("can't unmarshal ports expression: %w", err)
		}
	}

	if len(statsJSON) > 0 {
		if err := json.Unmarshal(statsJSON, &s.Stats); err != nil {
			return nil, fmt.Errorf("can't unmarshal stats: %w", err)
		}
	}

	return &s, nil
}
