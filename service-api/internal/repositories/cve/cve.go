// Package cve re-exports the CVE catalog, match, match-state, and sync-state
// repositories from their implementation subpackages.
package cve

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/catalog"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/matchstate"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/syncstate"
)

// CatalogRepository re-exports catalog.Repository.
type CatalogRepository = catalog.Repository

// CVE re-exports catalog.CVE.
type CVE = catalog.CVE

// CPELeaf re-exports catalog.CPELeaf.
type CPELeaf = catalog.CPELeaf

// KEVRow re-exports catalog.KEVRow.
type KEVRow = catalog.KEVRow

// EPSSRow re-exports catalog.EPSSRow.
type EPSSRow = catalog.EPSSRow

// VendorProduct re-exports catalog.VendorProduct.
type VendorProduct = catalog.VendorProduct

// MatchRepository re-exports match.Repository.
type MatchRepository = match.Repository

// Match re-exports match.Match.
type Match = match.Match

// MatchDetail re-exports match.Detail.
type MatchDetail = match.Detail

// SeverityCounts re-exports match.SeverityCounts.
type SeverityCounts = match.SeverityCounts

// TopCVE re-exports match.TopCVE.
type TopCVE = match.TopCVE

// MatchStateRepository re-exports matchstate.Repository.
type MatchStateRepository = matchstate.Repository

// SyncStateRepository re-exports syncstate.Repository.
type SyncStateRepository = syncstate.Repository

// SyncState re-exports syncstate.SyncState.
type SyncState = syncstate.SyncState

// ErrNotFound re-exports catalog.ErrNotFound.
var ErrNotFound = catalog.ErrNotFound

// NewPostgreSQLCatalog builds a catalog repository backed by pool.
func NewPostgreSQLCatalog(pool *pgxpool.Pool) CatalogRepository {
	return catalog.NewPostgreSQL(pool)
}

// NewPostgreSQLMatch builds a match repository backed by pool.
func NewPostgreSQLMatch(pool *pgxpool.Pool) MatchRepository {
	return match.NewPostgreSQL(pool)
}

// NewPostgreSQLMatchState builds a match-state repository backed by pool.
func NewPostgreSQLMatchState(pool *pgxpool.Pool) MatchStateRepository {
	return matchstate.NewPostgreSQL(pool)
}

// NewPostgreSQLSyncState builds a sync-state repository backed by pool.
func NewPostgreSQLSyncState(pool *pgxpool.Pool) SyncStateRepository {
	return syncstate.NewPostgreSQL(pool)
}
