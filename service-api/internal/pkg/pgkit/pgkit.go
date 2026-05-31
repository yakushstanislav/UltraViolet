// Package pgkit collects the small pgx adapter pieces that every repository
// package needs: the Querier interface (so a repo can be rebound to a pool or
// to a tx), and the error-mapping helpers that translate raw pgx/pgconn
// errors into stable sentinel errors.
//
// Historically these two concerns lived in separate packages (pgerr and
// pgxutil); both names are still importable as thin deprecated shims so old
// code keeps compiling, but new code should import pgkit directly.
package pgkit

import (
	"context"
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the subset of pgx satisfied by both *pgxpool.Pool and pgx.Tx so
// repositories can be rebound transactionally via a WithTx helper.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

var (
	// ErrNoRows is returned when a query expected a row but found none.
	ErrNoRows = pgx.ErrNoRows

	// ErrUniqueViolation is returned when a unique constraint is violated.
	ErrUniqueViolation = errors.New("row already exists")

	// ErrForeignKeyViolation is returned when a foreign key constraint is violated.
	ErrForeignKeyViolation = errors.New("foreign key violation")

	// ErrCheckViolation is returned when a CHECK constraint is violated.
	ErrCheckViolation = errors.New("check constraint violation")

	// ErrNotNullViolation is returned when a NOT NULL constraint is violated.
	ErrNotNullViolation = errors.New("not null violation")

	// ErrSerializationFailure is returned when a transaction cannot be serialized.
	ErrSerializationFailure = errors.New("serialization failure")

	// ErrDeadlockDetected is returned when PostgreSQL aborts due to deadlock.
	ErrDeadlockDetected = errors.New("deadlock detected")
)

// Handle maps low-level pgx errors to package-level sentinel errors so
// callers can react with errors.Is, while keeping the original pgconn error
// reachable via errors.As. We return a sentinelError whose Unwrap exposes
// both the sentinel (matches errors.Is) and the underlying error (matches
// errors.As for *pgconn.PgError, preserving constraint name / detail).
func Handle(err error) error {
	if err == nil {
		return nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgerrcode.UniqueViolation:
			return &sentinelError{sentinel: ErrUniqueViolation, cause: err}
		case pgerrcode.ForeignKeyViolation:
			return &sentinelError{sentinel: ErrForeignKeyViolation, cause: err}
		case pgerrcode.CheckViolation:
			return &sentinelError{sentinel: ErrCheckViolation, cause: err}
		case pgerrcode.NotNullViolation:
			return &sentinelError{sentinel: ErrNotNullViolation, cause: err}
		case pgerrcode.SerializationFailure:
			return &sentinelError{sentinel: ErrSerializationFailure, cause: err}
		case pgerrcode.DeadlockDetected:
			return &sentinelError{sentinel: ErrDeadlockDetected, cause: err}
		}
	}

	return err
}

// sentinelError pairs a pgkit sentinel with the original pgx/pgconn error.
// Its Is/Unwrap implementations make both reachable: errors.Is(e, sentinel)
// holds, and errors.As(e, &*pgconn.PgError) still recovers the raw error.
type sentinelError struct {
	sentinel error
	cause    error
}

func (e *sentinelError) Error() string {
	return e.sentinel.Error() + ": " + e.cause.Error()
}

func (e *sentinelError) Is(target error) bool {
	return target == e.sentinel
}

func (e *sentinelError) Unwrap() error {
	return e.cause
}
