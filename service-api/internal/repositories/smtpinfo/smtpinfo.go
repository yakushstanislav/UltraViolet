// Package smtpinfo stores SMTP capability snapshots, one row per service.
package smtpinfo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// SMTPInfo holds SMTP metadata captured for one service.
type SMTPInfo struct {
	ServiceID      uint64
	Banner         sql.NullString
	Capabilities   []string
	STARTTLS       bool
	AuthMethods    []string
	MaxMessageSize sql.NullInt64
	CapturedAt     time.Time
}

// Repository is the storage contract for SMTP info records.
type Repository interface {
	Upsert(ctx context.Context, info *SMTPInfo) error
	GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*SMTPInfo, error)
	// WithTx returns a Repository that routes every query through tx.
	WithTx(tx pgx.Tx) Repository
}

// PostgreSQL is the pgx-backed Repository implementation.
type PostgreSQL struct {
	db pgkit.Querier
}

// NewPostgreSQL builds a Repository.
func NewPostgreSQL(pool *pgxpool.Pool) *PostgreSQL {
	return &PostgreSQL{db: pool}
}

// WithTx returns a Repository that routes every query through tx.
func (p *PostgreSQL) WithTx(tx pgx.Tx) Repository {
	return &PostgreSQL{db: tx}
}

var smtpInfoColumns = []string{
	"service_id", "banner", "capabilities", "starttls", "auth_methods", "max_message_size", "captured_at",
}

// Upsert inserts or refreshes the SMTP snapshot for the service.
func (p *PostgreSQL) Upsert(ctx context.Context, info *SMTPInfo) error {
	capturedAt := info.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}

	query, args, err := sq.Insert("uv_smtp_info").
		Columns(smtpInfoColumns...).
		Values(
			info.ServiceID, info.Banner, info.Capabilities, info.STARTTLS,
			info.AuthMethods, info.MaxMessageSize, capturedAt,
		).
		Suffix(`ON CONFLICT (service_id) DO UPDATE SET
    banner           = EXCLUDED.banner,
    capabilities     = EXCLUDED.capabilities,
    starttls         = EXCLUDED.starttls,
    auth_methods     = EXCLUDED.auth_methods,
    max_message_size = EXCLUDED.max_message_size,
    captured_at      = EXCLUDED.captured_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert smtp info query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert smtp info: %w", pgkit.Handle(err))
	}

	return nil
}

// GetByServiceIDs returns a map of service_id → SMTPInfo.
func (p *PostgreSQL) GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*SMTPInfo, error) {
	out := make(map[uint64]*SMTPInfo, len(serviceIDs))

	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(smtpInfoColumns...).
		From("uv_smtp_info").
		Where("service_id = ANY(?)", serviceIDs).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get smtp info query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query smtp info: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var info SMTPInfo

		err := rows.Scan(
			&info.ServiceID,
			&info.Banner,
			&info.Capabilities,
			&info.STARTTLS,
			&info.AuthMethods,
			&info.MaxMessageSize,
			&info.CapturedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan smtp info row: %w", pgkit.Handle(err))
		}

		out[info.ServiceID] = &info
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate smtp info rows: %w", err)
	}

	return out, nil
}
