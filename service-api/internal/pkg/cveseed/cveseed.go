// Package cveseed optionally restores a pg_dump custom-format backup of the
// local NVD mirror (uv_cve, uv_cve_cpe) immediately after schema migrations,
// when the catalog is still empty. Paths come from CVE_CATALOG_SEED_FILE,
// CVE_CATALOG_SEED_DIR (newest *.dump), or the default mount
// /ServiceAPI/seed/cve-catalog.dump — see service-env/.env.example.
package cveseed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/postgresql"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// advisoryLockKey coordinates CVE catalog restore across concurrent app
// instances (e.g. multiple uv-api replicas on an empty database).
const advisoryLockKey int64 = 0x55_56_43_56_45_53_45 // "UVCVESE" packed

// TryRepairCVECatalogSyncState fixes uv_cve_sync_state when the catalog has
// rows but bootstrapped_at is still NULL (e.g. pg_restore succeeded and the
// follow-up UPDATE failed, or manual data load). Without this, cvesync would
// run a full NVD bootstrap on top of an already populated uv_cve.
func TryRepairCVECatalogSyncState(ctx context.Context, pool *pgxpool.Pool, log *zap.SugaredLogger) error {
	q, args, err := syncStateUpdateFromExistingCatalog(true)
	if err != nil {
		return fmt.Errorf("can't build CVE sync state repair query: %w", err)
	}

	tag, execErr := pool.Exec(ctx, q, args...)
	if execErr != nil {
		return fmt.Errorf("can't repair uv_cve_sync_state: %w", execErr)
	}

	if tag.RowsAffected() > 0 {
		log.Infow("Repaired uv_cve_sync_state for populated CVE catalog",
			zap.Int64("rows_affected", tag.RowsAffected()))
	}

	return nil
}

// MaybeRestore loads a custom-format pg_dump (--format=custom) into uv_cve
// and uv_cve_cpe when a seed file is resolved (see ResolveSeedDump), the file
// exists, and uv_cve has no rows. It updates uv_cve_sync_state so cvesync
// continues incrementally.
//
// While restoring, one pool connection is held for the advisory lock; long
// restores reduce the pool by one connection until completion.
func MaybeRestore(
	ctx context.Context,
	pool *pgxpool.Pool,
	pgCfg *postgresql.Config,
	seedFile string,
	seedDir string,
	log *zap.SugaredLogger,
) error {
	resolved, seedSource, resolveErr := ResolveSeedDump(seedFile, seedDir)
	if resolveErr != nil {
		return resolveErr
	}

	if resolved == "" {
		return nil
	}

	if _, err := os.Stat(resolved); err != nil {
		if os.IsNotExist(err) {
			if seedSource == "CVE_CATALOG_SEED_FILE" {
				log.Infow("CVE catalog seed file missing, skipping restore", zap.String("path", resolved))
			}

			return nil
		}

		return fmt.Errorf("can't stat CVE catalog seed file: %w", err)
	}

	if pgCfg == nil {
		return errors.New("nil PostgreSQL config")
	}

	pgRestorePath, err := exec.LookPath("pg_restore")
	if err != nil {
		return fmt.Errorf("pg_restore not found in PATH (install postgresql client tools): %w", err)
	}

	ac, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("can't acquire connection for CVE seed lock: %w", err)
	}

	defer ac.Release()

	pgxc := ac.Conn()

	_, err = pgxc.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey)
	if err != nil {
		return fmt.Errorf("can't acquire CVE catalog seed advisory lock: %w", err)
	}

	unlock := func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if _, unlockErr := pgxc.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, advisoryLockKey); unlockErr != nil {
			log.Warnw("Can't release CVE catalog seed advisory lock", zap.Error(unlockErr))
		}
	}

	defer unlock()

	countQuery, countArgs, err := sq.Select("COUNT(*)").From("uv_cve").ToSql()
	if err != nil {
		return fmt.Errorf("can't build uv_cve count query: %w", err)
	}

	var rowCount int64

	if scanErr := pgxc.QueryRow(ctx, countQuery, countArgs...).Scan(&rowCount); scanErr != nil {
		return fmt.Errorf("can't count uv_cve rows: %w", scanErr)
	}

	if rowCount > 0 {
		log.Infow("CVE catalog already populated, skipping seed restore", zap.Int64("rows", rowCount))

		return nil
	}

	log.Infow("Restoring CVE catalog from pg_dump seed",
		zap.String("path", resolved),
		zap.String("seed_source", seedSource),
	)

	cmd := exec.CommandContext(ctx, pgRestorePath,
		"--no-owner",
		"--data-only",
		"-h", pgCfg.Addr,
		"-p", strconv.FormatUint(pgCfg.Port, 10),
		"-U", pgCfg.Username,
		"-d", pgCfg.Database,
		"-t", "uv_cve",
		"-t", "uv_cve_cpe",
		resolved,
	)

	cmd.Env = append(os.Environ(),
		"PGPASSWORD="+pgCfg.Password,
		"PGSSLMODE=disable",
	)

	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		return fmt.Errorf("pg_restore failed: %s: %w", string(out), runErr)
	}

	if len(out) > 0 {
		log.Debugw("pg_restore output", zap.String("output", string(out)))
	}

	seedSyncStateQuery, seedSyncStateArgs, err := sq.Insert("uv_cve_sync_state").
		Columns("id").
		Values(1).
		Suffix("ON CONFLICT DO NOTHING").
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build seed cve sync state query: %w", err)
	}

	if _, seedExecErr := pgxc.Exec(ctx, seedSyncStateQuery, seedSyncStateArgs...); seedExecErr != nil {
		return fmt.Errorf("can't ensure uv_cve_sync_state row: %w", seedExecErr)
	}

	upd, updArgs, err := syncStateUpdateFromExistingCatalog(false)
	if err != nil {
		return fmt.Errorf("can't build post-restore sync state update: %w", err)
	}

	if _, updExecErr := pgxc.Exec(ctx, upd, updArgs...); updExecErr != nil {
		return fmt.Errorf("can't update uv_cve_sync_state after seed restore: %w", updExecErr)
	}

	log.Infow("CVE catalog seed restore finished")

	return nil
}

func syncStateUpdateFromExistingCatalog(repairOnly bool) (string, []any, error) {
	upd := sq.Update("uv_cve_sync_state").
		Set("bootstrapped_at", squirrel.Expr("NOW() AT TIME ZONE 'utc'")).
		Set("last_mod_start", squirrel.Expr("(SELECT MAX(last_modified_at) FROM uv_cve)")).
		Set("entries_done", squirrel.Expr("(SELECT COUNT(*)::int FROM uv_cve)")).
		Set("entries_total", squirrel.Expr("(SELECT COUNT(*)::int FROM uv_cve)")).
		Set("updated_at", squirrel.Expr("NOW() AT TIME ZONE 'utc'")).
		Where(squirrel.Eq{"id": 1})

	if repairOnly {
		upd = upd.Where(squirrel.Expr("bootstrapped_at IS NULL")).
			Where(squirrel.Expr("(SELECT COUNT(*) FROM uv_cve) > 0"))
	}

	return upd.ToSql()
}
