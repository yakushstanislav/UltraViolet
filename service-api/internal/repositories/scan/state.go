package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

// Claim atomically picks the oldest PENDING (or auto-resumable PAUSED) scan
// and transitions it to RUNNING.
//
// PAUSED scans are eligible only when auto_resume = true, which covers
// recoveries from RecoverStaleRunning, worker-shutdown finalisation, and
// explicit operator Resume requests. User-paused scans (auto_resume = false)
// are left alone until an operator calls Resume.
//
// For PENDING scans started_at is initialised to now. For resumed PAUSED
// scans the existing started_at is preserved so delta windows that depend on
// it stay consistent across resumes. The error column is cleared on claim so
// any prior "paused"/"interrupted" reason does not leak into a subsequent
// DONE state.
//
// Returns ErrNoPendingScan when no scan is available.
func (p *PostgreSQL) Claim(ctx context.Context) (*Scan, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't begin claim transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	selectSQL, selectArgs, err := sq.Select(scanColumns...).
		From("uv_scan").
		Where(squirrel.And{
			squirrel.Eq{"cancel_requested": false},
			squirrel.Or{
				squirrel.Eq{"status": StatusPending},
				squirrel.And{
					squirrel.Eq{"status": StatusPaused},
					squirrel.Eq{"auto_resume": true},
				},
			},
		}).
		OrderBy("id").
		Suffix("FOR UPDATE SKIP LOCKED").
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build claim select query: %w", err)
	}

	scanJob, err := scanRow(tx.QueryRow(ctx, selectSQL, selectArgs...))
	if errors.Is(err, pgkit.ErrNoRows) {
		return nil, ErrNoPendingScan
	}

	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	resumingFromPause := scanJob.Status == StatusPaused

	update := sq.Update("uv_scan").
		Set("status", StatusRunning).
		Set("pause_requested", false).
		Set("auto_resume", false).
		Set("error", nil).
		Where(squirrel.Eq{"id": scanJob.ID})

	if !resumingFromPause {
		update = update.Set("started_at", now).Set("progress_cursor", "")
	}

	updateSQL, updateArgs, err := update.ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build claim update query: %w", err)
	}

	if _, err = tx.Exec(ctx, updateSQL, updateArgs...); err != nil {
		return nil, fmt.Errorf("can't claim scan: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("can't commit claim transaction: %w", err)
	}

	scanJob.Status = StatusRunning
	scanJob.PauseRequested = false
	scanJob.AutoResume = false
	scanJob.Error = sql.NullString{}

	if !resumingFromPause {
		scanJob.StartedAt = sql.NullTime{Time: now, Valid: true}
		scanJob.ProgressCursor = ""
	}

	return scanJob, nil
}

// RecoverStaleRunning transitions scans that have been RUNNING longer than
// maxAge to PAUSED so the next available worker can resume them.
//
// auto_resume is set based on the original intent: if pause_requested was
// true at the moment of the crash, the operator explicitly wanted the scan
// paused, so it stays paused (auto_resume = false). Otherwise the scan was
// killed mid-flight and should be picked up automatically (auto_resume =
// true).
//
// Cancellation orphans (RUNNING + cancel_requested) are skipped here: they are
// owned by MarkAbandonedCanceled which closes them as CANCELED instead.
func (p *PostgreSQL) RecoverStaleRunning(ctx context.Context, maxAge time.Duration) (uint64, error) {
	if maxAge <= 0 {
		return 0, nil
	}

	now := time.Now().UTC()
	deadline := now.Add(-maxAge)

	query, args, err := sq.Update("uv_scan").
		Set("status", StatusPaused).
		Set("auto_resume", squirrel.Expr("NOT pause_requested")).
		Set("error", squirrel.Expr(
			"CASE WHEN pause_requested THEN ? ELSE ? END",
			PauseReasonByUser,
			PauseReasonInterrupted,
		)).
		Set("pause_requested", false).
		Where(squirrel.Eq{"status": StatusRunning, "cancel_requested": false}).
		Where("started_at IS NOT NULL").
		Where("started_at < ?", deadline).
		Where("finished_at IS NULL").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build recover stale running query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("can't recover stale running scans: %w", pgkit.Handle(err))
	}

	return uint64(tag.RowsAffected()), nil
}

// ReclaimAllRunning unconditionally transitions every RUNNING scan to PAUSED
// with auto_resume=true. Intended to be called once at worker startup so a
// scan left in RUNNING after a hard kill (where graceful finalisation did
// not run) is immediately resumable by the next claim instead of waiting
// for the SCANNER_RUNNING_TTL janitor window.
//
// Cancellation orphans (cancel_requested=true) are skipped so the
// abandoned-cancel janitor can finalise them as CANCELED.
//
// Returns the number of scans reclaimed.
func (p *PostgreSQL) ReclaimAllRunning(ctx context.Context) (uint64, error) {
	query, args, err := sq.Update("uv_scan").
		Set("status", StatusPaused).
		Set("auto_resume", true).
		Set("error", PauseReasonInterrupted).
		Set("pause_requested", false).
		Where(squirrel.Eq{"status": StatusRunning, "cancel_requested": false}).
		Where("finished_at IS NULL").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build reclaim running query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("can't reclaim running scans: %w", pgkit.Handle(err))
	}

	return uint64(tag.RowsAffected()), nil
}

// MarkAbandonedCanceled finalises RUNNING scans whose cancellation was
// requested but never observed by a worker (typically because the worker was
// restarted or killed before it could update the status).
//
// Returns the number of scans transitioned to CANCELED.
func (p *PostgreSQL) MarkAbandonedCanceled(ctx context.Context) (uint64, error) {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_scan").
		Set("status", StatusCanceled).
		Set("finished_at", squirrel.Expr("COALESCE(finished_at, ?)", now)).
		Set("error", squirrel.Expr("COALESCE(error, ?)", CancelReasonByUser)).
		Where(squirrel.Eq{"status": StatusRunning, "cancel_requested": true}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build mark abandoned canceled query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("can't mark abandoned cancellations: %w", pgkit.Handle(err))
	}

	return uint64(tag.RowsAffected()), nil
}

// RequestCancel marks a scan as cancelled.
//
// PENDING and PAUSED scans are transitioned to CANCELED in place. RUNNING
// scans only get the cancel_requested flag set; the worker observes the flag
// and stops the pipeline before flipping the status itself. Terminal scans
// (DONE, FAILED, CANCELED) yield ErrNotCancelable.
//
// The status returned is the post-call status of the scan.
func (p *PostgreSQL) RequestCancel(ctx context.Context, id uint64) (Status, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("can't begin cancel transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	lockSQL, lockArgs, err := sq.Select("status").
		From("uv_scan").
		Where(squirrel.Eq{"id": id}).
		Suffix("FOR UPDATE").
		ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build lock scan query: %w", err)
	}

	var current Status

	err = tx.QueryRow(ctx, lockSQL, lockArgs...).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}

	if err != nil {
		return "", fmt.Errorf("can't load scan for cancel: %w", pgkit.Handle(err))
	}

	switch current {
	case StatusPending, StatusPaused:
		return cancelIdleScan(ctx, tx, id)
	case StatusRunning:
		return flagRunningScanCancel(ctx, tx, id)
	default:
		return current, ErrNotCancelable
	}
}

// cancelIdleScan flips a PENDING or PAUSED scan straight to CANCELED in the
// same transaction RequestCancel opened. Such scans have no worker attached so
// no signal is necessary.
func cancelIdleScan(ctx context.Context, tx pgx.Tx, id uint64) (Status, error) {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_scan").
		Set("status", StatusCanceled).
		Set("finished_at", now).
		Set("error", squirrel.Expr("COALESCE(error, ?)", CancelReasonByUser)).
		Set("cancel_requested", true).
		Set("pause_requested", false).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build cancel idle scan query: %w", err)
	}

	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return "", fmt.Errorf("can't cancel idle scan: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("can't commit cancel transaction: %w", err)
	}

	return StatusCanceled, nil
}

// flagRunningScanCancel sets cancel_requested on a RUNNING scan; the worker
// polls IsCancelRequested and stops the pipeline.
func flagRunningScanCancel(ctx context.Context, tx pgx.Tx, id uint64) (Status, error) {
	query, args, err := sq.Update("uv_scan").
		Set("cancel_requested", true).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build flag running scan cancel query: %w", err)
	}

	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return "", fmt.Errorf("can't request running scan cancel: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("can't commit cancel transaction: %w", err)
	}

	return StatusRunning, nil
}

// IsCancelRequested returns the cancel_requested flag for a scan.
func (p *PostgreSQL) IsCancelRequested(ctx context.Context, id uint64) (bool, error) {
	query, args, err := sq.Select("cancel_requested").From("uv_scan").Where(squirrel.Eq{"id": id}).ToSql()
	if err != nil {
		return false, fmt.Errorf("can't build is cancel requested query: %w", err)
	}

	var requested bool

	err = p.pool.QueryRow(ctx, query, args...).Scan(&requested)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}

	if err != nil {
		return false, fmt.Errorf("can't read cancellation status: %w", pgkit.Handle(err))
	}

	return requested, nil
}

// RequestPause marks a RUNNING scan to be paused.
//
// Only RUNNING scans can be paused; the worker observes the flag and stops
// the pipeline before flipping the status to PAUSED itself via MarkPaused.
// PENDING / PAUSED / terminal scans yield ErrNotPauseable.
//
// The status returned is the post-call status of the scan.
func (p *PostgreSQL) RequestPause(ctx context.Context, id uint64) (Status, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("can't begin pause transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	lockSQL, lockArgs, err := sq.Select("status").
		From("uv_scan").
		Where(squirrel.Eq{"id": id}).
		Suffix("FOR UPDATE").
		ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build lock scan query: %w", err)
	}

	var current Status

	err = tx.QueryRow(ctx, lockSQL, lockArgs...).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}

	if err != nil {
		return "", fmt.Errorf("can't load scan for pause: %w", pgkit.Handle(err))
	}

	if current != StatusRunning {
		return current, ErrNotPauseable
	}

	query, args, err := sq.Update("uv_scan").
		Set("pause_requested", true).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build request pause query: %w", err)
	}

	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return "", fmt.Errorf("can't request scan pause: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("can't commit pause transaction: %w", err)
	}

	return StatusRunning, nil
}

// IsPauseRequested returns the pause_requested flag for a scan.
func (p *PostgreSQL) IsPauseRequested(ctx context.Context, id uint64) (bool, error) {
	query, args, err := sq.Select("pause_requested").From("uv_scan").Where(squirrel.Eq{"id": id}).ToSql()
	if err != nil {
		return false, fmt.Errorf("can't build is pause requested query: %w", err)
	}

	var requested bool

	err = p.pool.QueryRow(ctx, query, args...).Scan(&requested)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}

	if err != nil {
		return false, fmt.Errorf("can't read pause status: %w", pgkit.Handle(err))
	}

	return requested, nil
}

// RequestResume re-enables a scan that was paused (or whose pause was
// requested but not yet observed by a worker).
//
// Behaviour by current status:
//
//   - PAUSED                              -> sets auto_resume = true, clears
//     pause_requested and error, returns PAUSED so the next worker tick picks
//     the job up via Claim.
//   - RUNNING with pause_requested = true -> clears pause_requested, returns
//     RUNNING so the worker keeps going without flipping to PAUSED.
//   - everything else                     -> ErrNotResumable.
//
// The status returned is the post-call status of the scan.
func (p *PostgreSQL) RequestResume(ctx context.Context, id uint64) (Status, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("can't begin resume transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	lockSQL, lockArgs, err := sq.Select("status", "pause_requested").
		From("uv_scan").
		Where(squirrel.Eq{"id": id}).
		Suffix("FOR UPDATE").
		ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build lock scan query: %w", err)
	}

	var (
		current        Status
		pauseRequested bool
	)

	err = tx.QueryRow(ctx, lockSQL, lockArgs...).Scan(&current, &pauseRequested)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}

	if err != nil {
		return "", fmt.Errorf("can't load scan for resume: %w", pgkit.Handle(err))
	}

	switch {
	case current == StatusPaused, current == StatusRunning && pauseRequested:
		// proceed
	default:
		return current, ErrNotResumable
	}

	update := sq.Update("uv_scan").
		Set("pause_requested", false).
		Where(squirrel.Eq{"id": id})

	if current == StatusPaused {
		update = update.Set("auto_resume", true).Set("error", nil)
	}

	query, args, err := update.ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build resume query: %w", err)
	}

	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return "", fmt.Errorf("can't resume scan: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("can't commit resume transaction: %w", err)
	}

	return current, nil
}

// Restart resets a scan in-place so the worker re-runs it from scratch under
// the same id. All artefacts produced by previous runs (snapshots, change
// events, delta summary) are dropped in the same transaction; the row itself
// is rolled back to PENDING with timing/progress/error cleared.
//
// Allowed source states: DONE, FAILED, CANCELED, PAUSED. RUNNING and PENDING
// yield ErrNotRestartable — the caller should cancel a running scan first or
// just wait for the pending one to start.
func (p *PostgreSQL) Restart(ctx context.Context, id uint64) (Status, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("can't begin restart transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	lockSQL, lockArgs, err := sq.Select("status").
		From("uv_scan").
		Where(squirrel.Eq{"id": id}).
		Suffix("FOR UPDATE").
		ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build lock scan query: %w", err)
	}

	var current Status

	err = tx.QueryRow(ctx, lockSQL, lockArgs...).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}

	if err != nil {
		return "", fmt.Errorf("can't load scan for restart: %w", pgkit.Handle(err))
	}

	switch current {
	case StatusDone, StatusFailed, StatusCanceled, StatusPaused:
		// proceed
	default:
		return current, ErrNotRestartable
	}

	for _, childTable := range []string{
		"uv_service_snapshot",
		"uv_service_change_event",
		"uv_scan_delta_summary",
	} {
		deleteSQL, deleteArgs, qerr := sq.Delete(childTable).
			Where(squirrel.Eq{"scan_id": id}).
			ToSql()
		if qerr != nil {
			return "", fmt.Errorf("can't build delete %s query: %w", childTable, qerr)
		}

		if _, qerr := tx.Exec(ctx, deleteSQL, deleteArgs...); qerr != nil {
			return "", fmt.Errorf("can't wipe %s for restart: %w", childTable, pgkit.Handle(qerr))
		}
	}

	resetSQL, resetArgs, err := sq.Update("uv_scan").
		Set("status", StatusPending).
		Set("started_at", nil).
		Set("finished_at", nil).
		Set("error", nil).
		Set("stats", []byte("{}")).
		Set("stats_updated_at", nil).
		Set("cancel_requested", false).
		Set("pause_requested", false).
		Set("auto_resume", false).
		Set("progress_cursor", "").
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return "", fmt.Errorf("can't build restart reset query: %w", err)
	}

	if _, err := tx.Exec(ctx, resetSQL, resetArgs...); err != nil {
		return "", fmt.Errorf("can't reset scan for restart: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("can't commit restart transaction: %w", err)
	}

	return StatusPending, nil
}

// MarkPaused transitions a scan to PAUSED, clears the pause_requested flag,
// stores auto_resume so Claim knows whether to re-pick the scan, and records
// the supplied reason in the error column (overwriting any prior value so
// the discriminator stays accurate). finished_at is left untouched because
// paused scans are expected to be resumed.
//
// The transition is guarded against races with concurrent Cancel and Resume:
// only RUNNING scans without a pending cancel get flipped. If the guard
// rejects the row (RowsAffected == 0), the call is a silent no-op — the
// worker has already lost the race and the operator's decision wins.
func (p *PostgreSQL) MarkPaused(ctx context.Context, id uint64, reason string, autoResume bool) error {
	update := sq.Update("uv_scan").
		Set("status", StatusPaused).
		Set("pause_requested", false).
		Set("auto_resume", autoResume).
		Where(squirrel.Eq{"id": id, "status": StatusRunning, "cancel_requested": false})

	if reason != "" {
		update = update.Set("error", reason)
	}

	query, args, err := update.ToSql()
	if err != nil {
		return fmt.Errorf("can't build mark paused query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't mark scan as paused: %w", pgkit.Handle(err))
	}

	return nil
}
