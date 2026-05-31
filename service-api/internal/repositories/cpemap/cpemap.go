// Package cpemap loads uv_cpe_product_map rows for the in-process cpemap cache.
package cpemap

import (
	"context"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"

	pkgcpemap "github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cpemap"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Repository reads the mirrored product map table.
type Repository interface {
	LoadAll(ctx context.Context) (map[string][]pkgcpemap.Coord, error)
}

// PostgreSQLProductMap implements Repository.
type PostgreSQLProductMap struct {
	db pgkit.Querier
}

// NewPostgreSQLProductMap builds a Repository.
func NewPostgreSQLProductMap(pool *pgxpool.Pool) *PostgreSQLProductMap {
	return &PostgreSQLProductMap{db: pool}
}

var _ pkgcpemap.Loader = (*PostgreSQLProductMap)(nil)

// LoadAll returns every product_key → CPE coordinates row group.
func (p *PostgreSQLProductMap) LoadAll(ctx context.Context) (map[string][]pkgcpemap.Coord, error) {
	query, args, err := sq.Select("product_key", "vendor", "product").
		From("uv_cpe_product_map").
		OrderBy("product_key", "vendor", "product").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build list cpe product map query: %w", err)
	}

	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query cpe product map: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make(map[string][]pkgcpemap.Coord)

	for rows.Next() {
		var (
			key     string
			vendor  string
			product string
		)

		if err := rows.Scan(&key, &vendor, &product); err != nil {
			return nil, fmt.Errorf("can't scan cpe product map row: %w", pgkit.Handle(err))
		}

		out[key] = append(out[key], pkgcpemap.Coord{Vendor: vendor, Product: product})
	}

	return out, rows.Err()
}
