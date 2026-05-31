package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// ErrNotFound signals that user does not exist.
var ErrNotFound = pgkit.ErrNoRows

// ErrLastAdmin is returned by mutations that would leave the system with no
// admin (last admin demoted, deactivated, or deleted).
var ErrLastAdmin = errors.New("operation would remove the last remaining admin")

// AdminRole is the role string that ErrLastAdmin guards against.
const AdminRole = "admin"

// User maps `uv_user` row.
type User struct {
	ID           uint64
	Username     string
	PasswordHash string
	Role         string
	IsActive     bool
	LastLoginAt  sql.NullTime
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Repository defines user persistence operations.
type Repository interface {
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByID(ctx context.Context, id uint64) (*User, error)
	Count(ctx context.Context) (uint64, error)
	CountByRole(ctx context.Context, role string) (uint64, error)
	List(ctx context.Context, limit, offset uint64, q, role string) ([]*User, uint64, error)
	Create(ctx context.Context, user *User) (uint64, error)
	UpdateRole(ctx context.Context, id uint64, role string) error
	UpdateRoleSafe(ctx context.Context, id uint64, role string) error
	UpdateActive(ctx context.Context, id uint64, active bool) error
	UpdateActiveSafe(ctx context.Context, id uint64, active bool) error
	UpdatePassword(ctx context.Context, id uint64, passwordHash string) error
	Delete(ctx context.Context, id uint64) error
	TouchLastLogin(ctx context.Context, id uint64, at time.Time) error
}

// PostgreSQL is pgx-backed user repository.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL constructs user repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

var userColumns = []string{
	"id", "username", "password_hash", "role", "is_active", "last_login_at", "created_at", "updated_at",
}

// GetByUsername fetches user by unique username.
func (p *PostgreSQL) GetByUsername(ctx context.Context, username string) (*User, error) {
	query, args, err := sq.Select(userColumns...).From("uv_user").Where(squirrel.Eq{"username": username}).ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get user by username query: %w", err)
	}

	return scanRow(p.pool.QueryRow(ctx, query, args...))
}

// GetByID fetches user by id.
func (p *PostgreSQL) GetByID(ctx context.Context, id uint64) (*User, error) {
	query, args, err := sq.Select(userColumns...).From("uv_user").Where(squirrel.Eq{"id": id}).ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get user by id query: %w", err)
	}

	return scanRow(p.pool.QueryRow(ctx, query, args...))
}

// CountByRole returns how many users have the given role.
func (p *PostgreSQL) CountByRole(ctx context.Context, role string) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").From("uv_user").Where(squirrel.Eq{"role": role}).ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count users by role query: %w", err)
	}

	var count uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("can't count users by role: %w", pgkit.Handle(err))
	}

	return count, nil
}

// List returns a paginated list of users and the total count.
// q filters by username substring (case-insensitive); role filters by exact role value.
func (p *PostgreSQL) List(ctx context.Context, limit, offset uint64, q, role string) ([]*User, uint64, error) {
	if limit == 0 {
		limit = 100
	}

	pred := squirrel.And{}

	if q != "" {
		pred = append(pred, squirrel.Expr("LOWER(username) LIKE LOWER(?)", "%"+q+"%"))
	}

	if role != "" {
		pred = append(pred, squirrel.Eq{"role": role})
	}

	countQ := sq.Select("COUNT(*)").From("uv_user")
	if len(pred) > 0 {
		countQ = countQ.Where(pred)
	}

	countSQL, countArgs, err := countQ.ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build count users query: %w", err)
	}

	var total uint64

	if scanErr := p.pool.QueryRow(ctx, countSQL, countArgs...).Scan(&total); scanErr != nil {
		return nil, 0, fmt.Errorf("can't count users: %w", pgkit.Handle(scanErr))
	}

	listQ := sq.Select(userColumns...).
		From("uv_user").
		OrderBy("id").
		Limit(limit).
		Offset(offset)

	if len(pred) > 0 {
		listQ = listQ.Where(pred)
	}

	query, args, err := listQ.ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build list users query: %w", err)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("can't list users: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	var out []*User

	for rows.Next() {
		item, scanErr := scanRow(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("can't iterate users: %w", err)
	}

	return out, total, nil
}

// Count returns total number of users.
func (p *PostgreSQL) Count(ctx context.Context) (uint64, error) {
	query, args, err := sq.Select("COUNT(*)").From("uv_user").ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count users query: %w", err)
	}

	var count uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("can't count users: %w", pgkit.Handle(err))
	}

	return count, nil
}

// Create inserts new user row.
func (p *PostgreSQL) Create(ctx context.Context, user *User) (uint64, error) {
	now := time.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}

	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}

	query, args, err := sq.Insert("uv_user").
		Columns("username", "password_hash", "role", "is_active", "created_at", "updated_at").
		Values(user.Username, user.PasswordHash, user.Role, user.IsActive, user.CreatedAt, user.UpdatedAt).
		Suffix("RETURNING id").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build create user query: %w", err)
	}

	var id uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("can't create user: %w", pgkit.Handle(err))
	}

	return id, nil
}

// UpdateRole changes a user's role.
func (p *PostgreSQL) UpdateRole(ctx context.Context, id uint64, role string) error {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_user").
		Set("role", role).
		Set("updated_at", now).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update user role query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't update user role: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateActive toggles whether a user may sign in.
func (p *PostgreSQL) UpdateActive(ctx context.Context, id uint64, active bool) error {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_user").
		Set("is_active", active).
		Set("updated_at", now).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update user active query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't update user active: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdatePassword replaces the stored password hash.
func (p *PostgreSQL) UpdatePassword(ctx context.Context, id uint64, passwordHash string) error {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_user").
		Set("password_hash", passwordHash).
		Set("updated_at", now).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update user password query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't update user password: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete soft-disables a user account.
func (p *PostgreSQL) Delete(ctx context.Context, id uint64) error {
	return p.UpdateActive(ctx, id, false)
}

// UpdateRoleSafe changes a user's role and refuses to demote the last admin.
// All admin rows are locked FOR UPDATE so concurrent demotions of different
// admins cannot both pass the count check (TOCTOU): the second caller waits
// on the lock, then re-reads the count and rejects with ErrLastAdmin.
func (p *PostgreSQL) UpdateRoleSafe(ctx context.Context, id uint64, role string) error {
	return p.runInTx(ctx, func(tx pgx.Tx) error {
		current, err := lockUserForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}

		if current.Role == AdminRole && role != AdminRole {
			if err := ensureNotLastAdminTx(ctx, tx); err != nil {
				return err
			}
		}

		return updateRoleTx(ctx, tx, id, role)
	})
}

// UpdateActiveSafe toggles a user's is_active and refuses to deactivate the
// last admin. Uses the same admin lock as UpdateRoleSafe.
func (p *PostgreSQL) UpdateActiveSafe(ctx context.Context, id uint64, active bool) error {
	return p.runInTx(ctx, func(tx pgx.Tx) error {
		current, err := lockUserForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}

		if current.Role == AdminRole && !active {
			if err := ensureNotLastAdminTx(ctx, tx); err != nil {
				return err
			}
		}

		return updateActiveTx(ctx, tx, id, active)
	})
}

func (p *PostgreSQL) runInTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can't begin user tx: %w", pgkit.Handle(err))
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("can't commit user tx: %w", pgkit.Handle(err))
	}

	return nil
}

func lockUserForUpdate(ctx context.Context, tx pgx.Tx, id uint64) (*User, error) {
	query, args, err := sq.Select(userColumns...).
		From("uv_user").
		Where(squirrel.Eq{"id": id}).
		Suffix("FOR UPDATE").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build lock user query: %w", err)
	}

	return scanRow(tx.QueryRow(ctx, query, args...))
}

// ensureNotLastAdminTx locks every admin row and rejects with ErrLastAdmin
// when fewer than two would remain.
func ensureNotLastAdminTx(ctx context.Context, tx pgx.Tx) error {
	lockSQL, lockArgs, err := sq.Select("id").
		From("uv_user").
		Where(squirrel.Eq{"role": AdminRole, "is_active": true}).
		Suffix("FOR UPDATE").
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build admin lock query: %w", err)
	}

	rows, err := tx.Query(ctx, lockSQL, lockArgs...)
	if err != nil {
		return fmt.Errorf("can't lock admin rows: %w", pgkit.Handle(err))
	}

	var count uint64

	for rows.Next() {
		var ignored uint64
		if scanErr := rows.Scan(&ignored); scanErr != nil {
			rows.Close()

			return fmt.Errorf("can't scan admin row: %w", pgkit.Handle(scanErr))
		}

		count++
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return fmt.Errorf("can't iterate admin rows: %w", err)
	}

	if count <= 1 {
		return ErrLastAdmin
	}

	return nil
}

func updateRoleTx(ctx context.Context, tx pgx.Tx, id uint64, role string) error {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_user").
		Set("role", role).
		Set("updated_at", now).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update user role query: %w", err)
	}

	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't update user role: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

func updateActiveTx(ctx context.Context, tx pgx.Tx, id uint64, active bool) error {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_user").
		Set("is_active", active).
		Set("updated_at", now).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build update user active query: %w", err)
	}

	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't update user active: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// TouchLastLogin updates user last_login_at timestamp. Returns ErrNotFound
// when the user disappeared between login and this call so the auth service
// has the option to surface that fact in audit telemetry.
func (p *PostgreSQL) TouchLastLogin(ctx context.Context, id uint64, at time.Time) error {
	query, args, err := sq.Update("uv_user").
		Set("last_login_at", at.UTC()).
		Set("updated_at", at.UTC()).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build touch last login query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("can't update last login: %w", pgkit.Handle(err))
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRow(row rowScanner) (*User, error) {
	var u User

	err := row.Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&u.Role,
		&u.IsActive,
		&u.LastLoginAt,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgkit.ErrNoRows
		}

		return nil, fmt.Errorf("can't scan user row: %w", pgkit.Handle(err))
	}

	return &u, nil
}
