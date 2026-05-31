// Package scanschedule persists recurring scan schedules.
package scanschedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	scandto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/scan"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// ErrNotFound is returned when a schedule lookup misses.
var ErrNotFound = pgkit.ErrNoRows

// Schedule is one row from uv_scan_schedule.
type Schedule struct {
	ID              uint64
	Name            string
	Enabled         bool
	IntervalSeconds int
	Target          sql.NullString
	ScanSubnet      bool
	Mode            string
	SlowProfile     string
	TargetStrategy  string
	HostLimit       sql.NullInt64
	PortsExpr       []scandto.PortExprItem
	LastRunAt       sql.NullTime
	LastScanID      sql.NullInt64
	NextRunAt       time.Time
	CreatedBy       sql.NullInt64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CreateParams holds fields for inserting a schedule.
type CreateParams struct {
	Name            string
	Enabled         bool
	IntervalSeconds int
	Target          string
	ScanSubnet      bool
	Mode            string
	SlowProfile     string
	TargetStrategy  string
	HostLimit       uint64
	PortsExpr       []scandto.PortExprItem
	NextRunAt       time.Time
	CreatedBy       uint64
}

// UpdatePatch holds optional fields for PATCH updates.
type UpdatePatch struct {
	Name            *string
	Enabled         *bool
	IntervalSeconds *int
	Target          *string
	ScanSubnet      *bool
	Mode            *string
	SlowProfile     *string
	TargetStrategy  *string
	HostLimit       *uint64
	PortsExpr       []scandto.PortExprItem
	NextRunAt       *time.Time
}

// Repository is the storage contract for scan schedules.
type Repository interface {
	Create(ctx context.Context, params CreateParams) (uint64, error)
	GetByID(ctx context.Context, id uint64) (*Schedule, error)
	List(ctx context.Context, limit, offset uint64) ([]*Schedule, uint64, error)
	ListAll(ctx context.Context) ([]*Schedule, error)
	Update(ctx context.Context, id uint64, patch UpdatePatch) error
	SetEnabled(ctx context.Context, id uint64, enabled bool) error
	Delete(ctx context.Context, id uint64) error
	DueLocked(ctx context.Context, now time.Time, batchSize int) ([]*Schedule, error)
	ScheduleDue(ctx context.Context, id uint64, nextRunAt time.Time) error
	RecordRun(
		ctx context.Context,
		id uint64,
		scanID uint64,
		nextRunAt *time.Time,
	) error
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

var scheduleColumns = []string{
	"id", "name", "enabled", "interval_seconds", "target", "scan_subnet", "mode", "slow_profile",
	"target_strategy", "host_limit", "ports_expr", "last_run_at", "last_scan_id", "next_run_at",
	"created_by", "created_at", "updated_at",
}

// Create inserts a new schedule row.
func (p *PostgreSQL) Create(ctx context.Context, params CreateParams) (uint64, error) {
	portsJSON, err := json.Marshal(params.PortsExpr)
	if err != nil {
		return 0, fmt.Errorf("can't marshal ports expression: %w", err)
	}

	now := time.Now().UTC()

	var targetArg any
	if params.Target != "" {
		targetArg = params.Target
	}

	var hostLimitArg any
	if params.HostLimit > 0 {
		hostLimitArg = int64(params.HostLimit)
	}

	var createdByArg any
	if params.CreatedBy > 0 {
		createdByArg = int64(params.CreatedBy)
	}

	query, args, err := sq.Insert("uv_scan_schedule").
		Columns(
			"name", "enabled", "interval_seconds", "target", "scan_subnet", "mode", "slow_profile",
			"target_strategy", "host_limit", "ports_expr", "next_run_at", "created_by", "created_at", "updated_at",
		).
		Values(
			params.Name, params.Enabled, params.IntervalSeconds, targetArg, params.ScanSubnet,
			params.Mode, params.SlowProfile, params.TargetStrategy, hostLimitArg, portsJSON,
			params.NextRunAt.UTC(), createdByArg, now, now,
		).
		Suffix("RETURNING id").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build create scan schedule query: %w", err)
	}

	var id uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("can't create scan schedule: %w", pgkit.Handle(err))
	}

	return id, nil
}

// GetByID returns a schedule by primary key.
func (p *PostgreSQL) GetByID(ctx context.Context, id uint64) (*Schedule, error) {
	query, args, err := sq.Select(scheduleColumns...).
		From("uv_scan_schedule").
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get scan schedule query: %w", err)
	}

	return scanScheduleRow(p.pool.QueryRow(ctx, query, args...))
}

// List returns a paginated list of schedules and the total count.
func (p *PostgreSQL) List(ctx context.Context, limit, offset uint64) ([]*Schedule, uint64, error) {
	if limit == 0 {
		limit = 100
	}

	countSQL, countArgs, err := sq.Select("COUNT(*)").From("uv_scan_schedule").ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count scan schedules query: %w", err)
	}

	var total uint64

	if err = p.pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("can't count scan schedules: %w", pgkit.Handle(err))
	}

	query, args, err := sq.Select(scheduleColumns...).
		From("uv_scan_schedule").
		OrderBy("id DESC").
		Limit(limit).
		Offset(offset).
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list scan schedules query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list scan schedules: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*Schedule

	for rows.Next() {
		item, scanErr := scanScheduleRow(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate scan schedules: %w", err)
	}

	return out, total, nil
}

// ListAll returns every schedule ordered by id descending.
func (p *PostgreSQL) ListAll(ctx context.Context) ([]*Schedule, error) {
	query, args, err := sq.Select(scheduleColumns...).
		From("uv_scan_schedule").
		OrderBy("id DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list all scan schedules query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't list all scan schedules: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*Schedule

	for rows.Next() {
		item, scanErr := scanScheduleRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate scan schedules: %w", err)
	}

	return out, nil
}

// Update applies a partial patch to a schedule row.
func (p *PostgreSQL) Update(ctx context.Context, id uint64, patch UpdatePatch) error {
	builder := sq.Update("uv_scan_schedule").Where(squirrel.Eq{"id": id})

	if patch.Name != nil {
		builder = builder.Set("name", *patch.Name)
	}

	if patch.Enabled != nil {
		builder = builder.Set("enabled", *patch.Enabled)
	}

	if patch.IntervalSeconds != nil {
		builder = builder.Set("interval_seconds", *patch.IntervalSeconds)
	}

	if patch.Target != nil {
		if *patch.Target == "" {
			builder = builder.Set("target", nil)
		} else {
			builder = builder.Set("target", *patch.Target)
		}
	}

	if patch.ScanSubnet != nil {
		builder = builder.Set("scan_subnet", *patch.ScanSubnet)
	}

	if patch.Mode != nil {
		builder = builder.Set("mode", *patch.Mode)
	}

	if patch.SlowProfile != nil {
		builder = builder.Set("slow_profile", *patch.SlowProfile)
	}

	if patch.TargetStrategy != nil {
		builder = builder.Set("target_strategy", *patch.TargetStrategy)
	}

	if patch.HostLimit != nil {
		if *patch.HostLimit == 0 {
			builder = builder.Set("host_limit", nil)
		} else {
			builder = builder.Set("host_limit", int64(*patch.HostLimit))
		}
	}

	if len(patch.PortsExpr) > 0 {
		portsJSON, err := json.Marshal(patch.PortsExpr)
		if err != nil {
			return fmt.Errorf("can't marshal ports expression: %w", err)
		}

		builder = builder.Set("ports_expr", portsJSON)
	}

	if patch.NextRunAt != nil {
		builder = builder.Set("next_run_at", patch.NextRunAt.UTC())
	}

	builder = builder.Set("updated_at", time.Now().UTC())

	query, args, err := builder.ToSql()
	if err != nil {
		return fmt.Errorf("can't build update scan schedule query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't update scan schedule: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// SetEnabled toggles the enabled flag.
func (p *PostgreSQL) SetEnabled(ctx context.Context, id uint64, enabled bool) error {
	query, args, err := sq.Update("uv_scan_schedule").
		Set("enabled", enabled).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build set scan schedule enabled query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't set scan schedule enabled: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete removes a schedule row.
func (p *PostgreSQL) Delete(ctx context.Context, id uint64) error {
	query, args, err := sq.Delete("uv_scan_schedule").Where(squirrel.Eq{"id": id}).ToSql()
	if err != nil {
		return fmt.Errorf("can't build delete scan schedule query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't delete scan schedule: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// DueLocked claims due enabled schedules by advancing next_run_at inside one
// transaction so concurrent workers cannot enqueue the same schedule twice.
func (p *PostgreSQL) DueLocked(ctx context.Context, now time.Time, batchSize int) ([]*Schedule, error) {
	if batchSize <= 0 {
		batchSize = 10
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't begin due schedules transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	claimSQL := `
WITH claimed AS (
    SELECT id, interval_seconds
    FROM uv_scan_schedule
    WHERE enabled AND next_run_at <= $1
    ORDER BY next_run_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT $2
)
UPDATE uv_scan_schedule AS s
SET next_run_at = $1 + (c.interval_seconds || ' seconds')::interval,
    updated_at = $1
FROM claimed AS c
WHERE s.id = c.id
RETURNING ` + joinScheduleColumns("s") + `
`

	rows, err := tx.Query(ctx, claimSQL, now.UTC(), batchSize)
	if err != nil {
		return nil, fmt.Errorf("can't claim due scan schedules: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*Schedule

	for rows.Next() {
		item, scanErr := scanScheduleRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate due scan schedules: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("can't commit due schedules transaction: %w", err)
	}

	return out, nil
}

// ScheduleDue moves next_run_at back so a failed worker claim can retry soon.
func (p *PostgreSQL) ScheduleDue(ctx context.Context, id uint64, nextRunAt time.Time) error {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_scan_schedule").
		Set("next_run_at", nextRunAt.UTC()).
		Set("updated_at", now).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build schedule due scan schedule query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't schedule scan due: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

func joinScheduleColumns(alias string) string {
	parts := make([]string, 0, len(scheduleColumns))
	for _, column := range scheduleColumns {
		parts = append(parts, alias+"."+column)
	}

	return strings.Join(parts, ", ")
}

// RecordRun updates bookkeeping after a schedule fires. When nextRunAt is nil
// the caller has already advanced next_run_at (worker claim path).
func (p *PostgreSQL) RecordRun(ctx context.Context, id, scanID uint64, nextRunAt *time.Time) error {
	now := time.Now().UTC()

	builder := sq.Update("uv_scan_schedule").
		Set("last_run_at", now).
		Set("last_scan_id", scanID).
		Set("updated_at", now).
		Where(squirrel.Eq{"id": id})

	if nextRunAt != nil {
		builder = builder.Set("next_run_at", nextRunAt.UTC())
	}

	query, args, err := builder.ToSql()
	if err != nil {
		return fmt.Errorf("can't build record scan schedule run query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't record scan schedule run: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanScheduleRow(row rowScanner) (*Schedule, error) {
	var (
		item          Schedule
		portsExprJSON []byte
	)

	err := row.Scan(
		&item.ID,
		&item.Name,
		&item.Enabled,
		&item.IntervalSeconds,
		&item.Target,
		&item.ScanSubnet,
		&item.Mode,
		&item.SlowProfile,
		&item.TargetStrategy,
		&item.HostLimit,
		&portsExprJSON,
		&item.LastRunAt,
		&item.LastScanID,
		&item.NextRunAt,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgkit.ErrNoRows
		}

		return nil, fmt.Errorf("can't scan scan schedule row: %w", pgkit.Handle(err))
	}

	if len(portsExprJSON) > 0 {
		if err := json.Unmarshal(portsExprJSON, &item.PortsExpr); err != nil {
			return nil, fmt.Errorf("can't unmarshal ports expression: %w", err)
		}
	}

	return &item, nil
}
