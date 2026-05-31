// Package sshinfo stores SSH-level metadata observed during probing.
package sshinfo

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

// SSHInfo holds SSH-level metadata captured for one service.
type SSHInfo struct {
	ServiceID          uint64
	ServerVersion      sql.NullString
	HostKeyType        sql.NullString
	HostKeyFingerprint sql.NullString
	KexAlgorithms      []string
	HostKeyAlgorithms  []string
	CapturedAt         time.Time
}

// Repository is the storage contract for SSH info records.
type Repository interface {
	Upsert(ctx context.Context, info *SSHInfo) error
	GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*SSHInfo, error)
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

var sshInfoColumns = []string{
	"service_id", "server_version", "host_key_type", "host_key_fingerprint",
	"kex_algorithms", "host_key_algorithms", "captured_at",
}

// Upsert inserts or refreshes the SSH info snapshot for the service.
func (p *PostgreSQL) Upsert(ctx context.Context, info *SSHInfo) error {
	query, args, err := sq.Insert("uv_ssh_info").
		Columns(sshInfoColumns...).
		Values(
			info.ServiceID, info.ServerVersion, info.HostKeyType,
			info.HostKeyFingerprint, info.KexAlgorithms, info.HostKeyAlgorithms, info.CapturedAt,
		).
		Suffix(`ON CONFLICT (service_id) DO UPDATE SET
    server_version       = EXCLUDED.server_version,
    host_key_type        = EXCLUDED.host_key_type,
    host_key_fingerprint = EXCLUDED.host_key_fingerprint,
    kex_algorithms       = EXCLUDED.kex_algorithms,
    host_key_algorithms  = EXCLUDED.host_key_algorithms,
    captured_at          = EXCLUDED.captured_at`).
		ToSql()
	if err != nil {
		return fmt.Errorf("can't build upsert ssh info query: %w", err)
	}

	if _, err := p.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("can't upsert ssh info: %w", pgkit.Handle(err))
	}

	return nil
}

// GetByServiceIDs returns a map of service_id → SSHInfo.
func (p *PostgreSQL) GetByServiceIDs(ctx context.Context, serviceIDs []uint64) (map[uint64]*SSHInfo, error) {
	out := make(map[uint64]*SSHInfo, len(serviceIDs))

	if len(serviceIDs) == 0 {
		return out, nil
	}

	query, args, err := sq.Select(sshInfoColumns...).
		From("uv_ssh_info").
		Where("service_id = ANY(?)", serviceIDs).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build get ssh info query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query ssh info: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	for rows.Next() {
		var info SSHInfo

		err := rows.Scan(
			&info.ServiceID,
			&info.ServerVersion,
			&info.HostKeyType,
			&info.HostKeyFingerprint,
			&info.KexAlgorithms,
			&info.HostKeyAlgorithms,
			&info.CapturedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("can't scan ssh info row: %w", pgkit.Handle(err))
		}

		out[info.ServiceID] = &info
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate ssh info rows: %w", err)
	}

	return out, nil
}
