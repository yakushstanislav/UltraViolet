package refreshtoken

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

// ErrNotFound signals that refresh token does not exist.
var ErrNotFound = pgkit.ErrNoRows

// RefreshToken maps `uv_refresh_token` row.
type RefreshToken struct {
	ID        uint64
	UserID    uint64
	TokenHash string
	ExpiresAt time.Time
	RevokedAt sql.NullTime
	CreatedAt time.Time
}

// Repository defines refresh token persistence operations.
type Repository interface {
	Create(ctx context.Context, token *RefreshToken) (uint64, error)
	GetActiveByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeByID(ctx context.Context, id uint64) error
	RevokeByUserID(ctx context.Context, userID uint64) (int64, error)
	ConsumeByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RotateByHash(ctx context.Context, oldHash string, replacement *RefreshToken) (*RefreshToken, uint64, error)
}

// PostgreSQL is pgx-backed refresh token repository.
type PostgreSQL struct {
	pool *pgxpool.Pool
}

// NewPostgreSQL constructs refresh token repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{pool: pool}
}

var tokenColumns = []string{"id", "user_id", "token_hash", "expires_at", "revoked_at", "created_at"}

// Create inserts refresh token row.
func (p *PostgreSQL) Create(ctx context.Context, token *RefreshToken) (uint64, error) {
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}

	query, args, err := sq.Insert("uv_refresh_token").
		Columns("user_id", "token_hash", "expires_at", "revoked_at", "created_at").
		Values(token.UserID, token.TokenHash, token.ExpiresAt.UTC(), token.RevokedAt, token.CreatedAt.UTC()).
		Suffix("RETURNING id").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build create refresh token query: %w", err)
	}

	var id uint64

	if err := p.pool.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("can't create refresh token: %w", pgkit.Handle(err))
	}

	return id, nil
}

// GetActiveByHash returns active session by token hash.
func (p *PostgreSQL) GetActiveByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	now := time.Now().UTC()

	query, args, err := sq.Select(tokenColumns...).
		From("uv_refresh_token").
		Where(squirrel.Eq{"token_hash": tokenHash}).
		Where("revoked_at IS NULL").
		Where("expires_at > ?", now).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get active refresh token query: %w", err)
	}

	return scanRow(p.pool.QueryRow(ctx, query, args...))
}

// ConsumeByHash atomically revokes the active refresh token with the given
// hash and returns the consumed row, ensuring a token can be redeemed at most
// once even under concurrent rotation.
func (p *PostgreSQL) ConsumeByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	now := time.Now().UTC()

	query, args, err := sq.Update("uv_refresh_token").
		Set("revoked_at", now).
		Where(squirrel.Eq{"token_hash": tokenHash}).
		Where("revoked_at IS NULL").
		Where("expires_at > ?", now).
		Suffix("RETURNING id, user_id, token_hash, expires_at, revoked_at, created_at").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build consume refresh token query: %w", err)
	}

	return scanRow(p.pool.QueryRow(ctx, query, args...))
}

// RotateByHash atomically revokes the active refresh token identified by
// oldHash and inserts replacement as its successor inside a single
// transaction. The consumed session and the new row's id are returned. If
// either step fails the transaction rolls back, so a caller observing an
// error knows the user's old token is still valid and a retry is safe.
func (p *PostgreSQL) RotateByHash(ctx context.Context, oldHash string, replacement *RefreshToken) (*RefreshToken, uint64, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("can't begin rotate refresh token tx: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()

	consumeSQL, consumeArgs, err := sq.Update("uv_refresh_token").
		Set("revoked_at", now).
		Where(squirrel.Eq{"token_hash": oldHash}).
		Where("revoked_at IS NULL").
		Where("expires_at > ?", now).
		Suffix("RETURNING id, user_id, token_hash, expires_at, revoked_at, created_at").
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build rotate consume query: %w", err)
	}

	consumed, err := scanRow(tx.QueryRow(ctx, consumeSQL, consumeArgs...))
	if err != nil {
		return nil, 0, err
	}

	if replacement.CreatedAt.IsZero() {
		replacement.CreatedAt = now
	}

	insertSQL, insertArgs, err := sq.Insert("uv_refresh_token").
		Columns("user_id", "token_hash", "expires_at", "revoked_at", "created_at").
		Values(replacement.UserID, replacement.TokenHash, replacement.ExpiresAt.UTC(), replacement.RevokedAt, replacement.CreatedAt.UTC()).
		Suffix("RETURNING id").
		ToSql()
	if err != nil {
		return nil, 0, fmt.Errorf("can't build rotate insert query: %w", err)
	}

	var newID uint64

	if err := tx.QueryRow(ctx, insertSQL, insertArgs...).Scan(&newID); err != nil {
		return nil, 0, fmt.Errorf("can't insert replacement refresh token: %w", pgkit.Handle(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("can't commit rotate refresh token tx: %w", err)
	}

	return consumed, newID, nil
}

// RevokeByID marks refresh token as revoked.
func (p *PostgreSQL) RevokeByID(ctx context.Context, id uint64) error {
	query, args, err := sq.Update("uv_refresh_token").
		Set("revoked_at", squirrel.Expr("COALESCE(revoked_at, ?)", time.Now().UTC())).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build revoke refresh token query: %w", err)
	}

	if _, err := p.pool.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't revoke refresh token: %w", pgkit.Handle(err))
	}

	return nil
}

// RevokeByUserID revokes every still-active refresh token for the given user
// and returns the count of newly-revoked rows. Idempotent: tokens already
// revoked are left alone (COALESCE preserves the original revoked_at).
func (p *PostgreSQL) RevokeByUserID(ctx context.Context, userID uint64) (int64, error) {
	query, args, err := sq.Update("uv_refresh_token").
		Set("revoked_at", time.Now().UTC()).
		Where(squirrel.Eq{"user_id": userID}).
		Where("revoked_at IS NULL").
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build revoke refresh tokens by user query: %w", err)
	}

	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("can't revoke refresh tokens by user: %w", pgkit.Handle(err))
	}

	return tag.RowsAffected(), nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRow(row rowScanner) (*RefreshToken, error) {
	var t RefreshToken

	err := row.Scan(
		&t.ID,
		&t.UserID,
		&t.TokenHash,
		&t.ExpiresAt,
		&t.RevokedAt,
		&t.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgkit.ErrNoRows
		}

		return nil, fmt.Errorf("can't scan refresh token row: %w", pgkit.Handle(err))
	}

	return &t, nil
}
