package postgresql

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds PostgreSQL connection settings.
type Config struct {
	Addr           string `env:"POSTGRES_ADDR"            env-required:"true"`
	Port           uint64 `env:"POSTGRES_PORT"            env-required:"true"`
	Username       string `env:"POSTGRES_USERNAME"        env-required:"true"`
	Password       string `env:"POSTGRES_PASSWORD"        env-required:"true"`
	Database       string `env:"POSTGRES_DATABASE"        env-required:"true"`
	SchemaPath     string `env:"POSTGRES_SCHEMA_PATH"`
	MaxConnections uint64 `env:"POSTGRES_MAX_CONNECTIONS" env-required:"true"`
}

// Pool tuning defaults. Hardcoded rather than env-configured to keep operator
// surface small; revisit only if production telemetry shows pool waits or
// reconnect storms.
const (
	poolMaxConnIdleTime       = 5 * time.Minute
	poolMaxConnLifetime       = 30 * time.Minute
	poolMaxConnLifetimeJitter = 5 * time.Minute
	poolHealthCheckPeriod     = 30 * time.Second
	poolMinConnsFloor         = int32(2)
	poolMinConnsDivisor       = int32(8)
)

// NewPostgreSQL opens a new connection pool.
func NewPostgreSQL(ctx context.Context, config *Config) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("can't parse pgx config: %w", err)
	}

	poolCfg.ConnConfig.Host = config.Addr
	poolCfg.ConnConfig.Port = uint16(config.Port)
	poolCfg.ConnConfig.User = config.Username
	poolCfg.ConnConfig.Password = config.Password
	poolCfg.ConnConfig.Database = config.Database
	poolCfg.ConnConfig.TLSConfig = nil

	if config.MaxConnections > 0 {
		poolCfg.MaxConns = int32(config.MaxConnections)
	}

	poolCfg.MinConns = minConns(poolCfg.MaxConns)
	poolCfg.MaxConnIdleTime = poolMaxConnIdleTime
	poolCfg.MaxConnLifetime = poolMaxConnLifetime
	poolCfg.MaxConnLifetimeJitter = poolMaxConnLifetimeJitter
	poolCfg.HealthCheckPeriod = poolHealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("can't connect to PostgreSQL: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()

		return nil, fmt.Errorf("can't ping PostgreSQL: %w", err)
	}

	return pool, nil
}

// minConns derives a warm-pool floor from the configured maximum so that bursty
// fan-outs (dashboard, facet endpoints) do not pay TCP handshake latency.
func minConns(maxConns int32) int32 {
	candidate := maxConns / poolMinConnsDivisor
	if candidate < poolMinConnsFloor {
		candidate = poolMinConnsFloor
	}

	if maxConns > 0 && candidate > maxConns {
		candidate = maxConns
	}

	return candidate
}

// migrationDSN returns a properly URL-escaped DSN for golang-migrate.
func migrationDSN(config *Config) string {
	u := url.URL{
		Scheme:   "pgx5",
		User:     url.UserPassword(config.Username, config.Password),
		Host:     net.JoinHostPort(config.Addr, strconv.FormatUint(config.Port, 10)),
		Path:     "/" + config.Database,
		RawQuery: "sslmode=disable",
	}

	return u.String()
}
