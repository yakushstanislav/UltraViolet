package postgresql

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // register pgx migration driver
	_ "github.com/golang-migrate/migrate/v4/source/file"     // register file migration source
)

// Migrate applies the schema migrations from config.SchemaPath.
//
// If SchemaPath is empty the call is a no-op so unit tests and the scanner
// process can connect to an already-migrated database without re-running.
func Migrate(_ context.Context, config *Config) error {
	if config.SchemaPath == "" {
		return nil
	}

	source := "file://" + config.SchemaPath

	m, err := migrate.New(source, migrationDSN(config))
	if err != nil {
		return fmt.Errorf("can't create migrator: %w", err)
	}

	defer func() {
		_, _ = m.Close()
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("can't apply migrations: %w", err)
	}

	return nil
}
