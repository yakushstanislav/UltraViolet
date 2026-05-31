// Package cve resolves service fingerprints against the mirrored NVD catalog
// and persists the results into uv_service_cve. Matching is strict: an empty
// captured version is never considered to match anything.
package cve

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/cpemap"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/riskmetrics"
	cvecatalog "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/catalog"
	cvematch "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/match"
	cvematchstate "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/matchstate"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/servicefingerprint"
	hostsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/host"
)

// tokenSplitRE splits fingerprint product/edition strings for target_sw checks
// so "python-requests" does not substring-match "python".
var tokenSplitRE = regexp.MustCompile(`[-_./ +]`)

// MatcherConfig holds tuning parameters for CVE matching.
type MatcherConfig struct {
	MinConfidence int16 `env:"CVE_MATCH_MIN_CONFIDENCE" env-default:"0"`
}

// HostRiskAggregator recomputes persisted host scores after service risk changes.
type HostRiskAggregator interface {
	AggregateForService(ctx context.Context, serviceID uint64) error
}

// Matcher applies cpemap to a fingerprint and persists the resulting CVE
// associations via the repository.
type Matcher struct {
	cfg          MatcherConfig
	pool         *pgxpool.Pool
	fingerprints servicefingerprint.Repository
	catalog      cvecatalog.Repository
	matches      cvematch.Repository
	matchState   cvematchstate.Repository
	services     service.Repository
	hostRisk     HostRiskAggregator
}

// NewMatcher builds a Matcher.
func NewMatcher(
	cfg MatcherConfig,
	pool *pgxpool.Pool,
	fingerprints servicefingerprint.Repository,
	catalog cvecatalog.Repository,
	matches cvematch.Repository,
	matchState cvematchstate.Repository,
	services service.Repository,
	hostRisk HostRiskAggregator,
) *Matcher {
	return &Matcher{
		cfg:          cfg,
		pool:         pool,
		fingerprints: fingerprints,
		catalog:      catalog,
		matches:      matches,
		matchState:   matchState,
		services:     services,
		hostRisk:     hostRisk,
	}
}

// MatchService recomputes the CVE association set for one service. The
// fingerprint lookup happens inside this call so callers (ingest hook,
// periodic worker) can be uniform.
//
// Since migration 16 a service can carry several technology components
// (web_server + cms + runtime + js_library + …). Matching runs once per
// component and the resulting CVE sets are unioned, keeping the highest
// confidence per cve_id so the same finding isn't recorded twice.
//
// As a side effect the service's CVE-driven risk score is refolded so the
// dashboard and sort-by-risk views immediately reflect new findings.
func (m *Matcher) MatchService(ctx context.Context, serviceID uint64) (int, error) {
	byService, err := m.fingerprints.GetByServiceIDs(ctx, []uint64{serviceID})
	if err != nil {
		return 0, fmt.Errorf("can't load fingerprint: %w", err)
	}

	components := byService[serviceID]
	if len(components) == 0 {
		if persistErr := m.persistMatches(ctx, serviceID, nil, ""); persistErr != nil {
			return 0, persistErr
		}

		if m.hostRisk != nil {
			_ = m.hostRisk.AggregateForService(hostsvc.WithTrigger(ctx, riskmetrics.TriggerCVEMatch), serviceID)
		}

		return 0, nil
	}

	bestByCVE := make(map[string]cvematch.Match)

	for _, fp := range components {
		if fp == nil || fp.Product == "" {
			continue
		}

		matches, err := m.computeMatches(ctx, fp)
		if err != nil {
			return 0, err
		}

		for _, match := range matches {
			if prev, exists := bestByCVE[match.CVEID]; exists && prev.Confidence >= match.Confidence {
				continue
			}

			bestByCVE[match.CVEID] = match
		}
	}

	merged := make([]cvematch.Match, 0, len(bestByCVE))
	for _, match := range bestByCVE {
		merged = append(merged, match)
	}

	setHash := servicefingerprint.SetHashOfComponents(components)

	if err := m.persistMatches(ctx, serviceID, merged, setHash); err != nil {
		return 0, err
	}

	if err := m.fingerprints.SetFingerprintHash(ctx, serviceID, setHash); err != nil {
		return 0, fmt.Errorf("can't backfill fingerprint hash: %w", err)
	}

	if m.hostRisk != nil {
		_ = m.hostRisk.AggregateForService(hostsvc.WithTrigger(ctx, riskmetrics.TriggerCVEMatch), serviceID)
	}

	return len(merged), nil
}

func (m *Matcher) persistMatches(ctx context.Context, serviceID uint64, matches []cvematch.Match, fingerprintHash string) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can't begin cve match transaction: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if err := m.matches.WithTx(tx).ReplaceForService(ctx, serviceID, matches); err != nil {
		return fmt.Errorf("can't replace service cve matches: %w", err)
	}

	if fingerprintHash == "" {
		if err := m.matchState.WithTx(tx).Delete(ctx, serviceID); err != nil {
			return fmt.Errorf("can't delete service match state: %w", err)
		}
	} else {
		matchedAt := time.Now().UTC()

		if len(matches) > 0 && !matches[0].MatchedAt.IsZero() {
			matchedAt = matches[0].MatchedAt
		}

		if err := m.matchState.WithTx(tx).Upsert(ctx, serviceID, fingerprintHash, matchedAt); err != nil {
			return fmt.Errorf("can't upsert service match state: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("can't commit cve match transaction: %w", err)
	}

	return nil
}

// versionlessConfidence is the score recorded when a fingerprint has a
// known product but no captured version, and the catalog leaf is a
// catch-all applicability claim (vulnerable=true with no exact pin and no
// bounds). Kept low so dashboards and sort-by-confidence views can
// down-rank these findings without dropping them.
const versionlessConfidence int16 = 30

func (m *Matcher) computeMatches(ctx context.Context, fp *servicefingerprint.Fingerprint) ([]cvematch.Match, error) {
	version := strings.TrimSpace(fp.Version.String)
	hasVersion := version != ""

	_, backportSuspected := cpemap.NormalizeVersion(version)

	coords, ok := cpemap.Lookup(fp.Product)
	if !ok || len(coords) == 0 {
		return nil, nil
	}

	pairs := make([]cvecatalog.VendorProduct, 0, len(coords))

	for _, coord := range coords {
		pairs = append(pairs, cvecatalog.VendorProduct{
			Vendor:  coord.Vendor,
			Product: coord.Product,
		})
	}

	leaves, err := m.catalog.LeavesByVendorProducts(ctx, pairs)
	if err != nil {
		return nil, fmt.Errorf("can't load cpe leaves: %w", err)
	}

	if len(leaves) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	bestByCVE := make(map[string]cvematch.Match, len(leaves))

	for _, leaf := range leaves {
		if !leaf.Vulnerable {
			continue
		}

		if !targetSWCompatible(nullStr(leaf.TargetSW), fp) {
			continue
		}

		rng := cpemap.Range{
			ExactVersion:          nullStr(leaf.ExactVersion),
			VersionStartIncluding: nullStr(leaf.VersionStartIncluding),
			VersionStartExcluding: nullStr(leaf.VersionStartExcluding),
			VersionEndIncluding:   nullStr(leaf.VersionEndIncluding),
			VersionEndExcluding:   nullStr(leaf.VersionEndExcluding),
		}

		versionless := false

		if !cpemap.VersionMatches(version, rng) {
			// Version-less fallback: a fingerprint with a known product but
			// no captured version still gets attributed against catch-all
			// applicability claims (vulnerable=true with no pin and no
			// bounds), at a deliberately low confidence so dashboards can
			// tell apart "version pinpointed" from "best-effort".
			if hasVersion || !cpemap.IsCatchAll(rng) {
				continue
			}

			versionless = true
		}

		var confidence int16
		if versionless {
			confidence = versionlessConfidence
		} else {
			confidence = matchConfidence(rng, backportSuspected, targetSWWeak(nullStr(leaf.TargetSW), fp))
		}

		if m.cfg.MinConfidence > 0 && confidence < m.cfg.MinConfidence {
			continue
		}

		prev, exists := bestByCVE[leaf.CVEID]
		if exists && prev.Confidence >= confidence {
			continue
		}

		matchedVersion := sql.NullString{String: version, Valid: hasVersion}

		bestByCVE[leaf.CVEID] = cvematch.Match{
			CVEID:          leaf.CVEID,
			MatchedVersion: matchedVersion,
			Confidence:     confidence,
			MatchedAt:      now,
		}
	}

	if len(bestByCVE) == 0 {
		return nil, nil
	}

	cveIDs := make([]string, 0, len(bestByCVE))

	for id := range bestByCVE {
		cveIDs = append(cveIDs, id)
	}

	cves, err := m.catalog.GetByIDs(ctx, cveIDs)
	if err != nil {
		return nil, fmt.Errorf("can't load cves: %w", err)
	}

	for _, id := range cveIDs {
		cve, ok := cves[id]
		if !ok {
			delete(bestByCVE, id)

			continue
		}

		match := bestByCVE[id]
		match.Severity, match.CVSSScore = bestCVSSFields(cve)
		match.KEVAddedAt = cve.KEVAddedAt
		match.EPSSScore = cve.EPSSScore
		match.EPSSPercentile = cve.EPSSPercentile
		bestByCVE[id] = match
	}

	out := make([]cvematch.Match, 0, len(bestByCVE))

	for _, match := range bestByCVE {
		out = append(out, match)
	}

	return out, nil
}

func matchConfidence(rng cpemap.Range, backportSuspected, targetSWWeak bool) int16 {
	conf := int16(60)

	switch {
	case rng.ExactVersion != "":
		conf = 100
	case rng.VersionStartIncluding != "" && rng.VersionEndIncluding != "":
		conf = 80
	case rng.VersionStartIncluding != "" || rng.VersionEndIncluding != "":
		conf = 60
	case rng.VersionStartExcluding != "" && rng.VersionEndExcluding != "":
		conf = 80
	case rng.VersionStartExcluding != "" || rng.VersionEndExcluding != "":
		conf = 60
	}

	if backportSuspected {
		conf -= 40
	}

	if targetSWWeak {
		conf -= 15
	}

	if conf < 0 {
		conf = 0
	}

	return conf
}

func bestCVSSFields(cve *cvecatalog.CVE) (sql.NullString, sql.NullFloat64) {
	if cve == nil {
		return sql.NullString{}, sql.NullFloat64{}
	}

	if cve.CVSSv40Severity.Valid || cve.CVSSv40Score.Valid {
		return cve.CVSSv40Severity, cve.CVSSv40Score
	}

	if cve.CVSSv31Severity.Valid || cve.CVSSv31Score.Valid {
		return cve.CVSSv31Severity, cve.CVSSv31Score
	}

	return cve.CVSSv3Severity, cve.CVSSv3Score
}

func nullStr(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}

	return ns.String
}

// targetSWCompatible drops leaves whose `target_sw` is a specific runtime that
// is provably incompatible with the fingerprint (e.g. a "target_sw=java" leaf
// against a service we know is plain PostgreSQL server). When the leaf has
// no target_sw, or the fingerprint doesn't reveal a runtime, the leaf is
// kept — wrongly dropping leaves here would tank recall on already-thin
// inventories.
var unrelatedTargetSWs = map[string]struct{}{
	"java":       {},
	"python":     {},
	"php":        {},
	"node.js":    {},
	"nodejs":     {},
	"javascript": {},
	"ruby":       {},
	"perl":       {},
	"go":         {},
	"erlang":     {},
	"rust":       {},
	"dotnet":     {},
	".net":       {},
	"wordpress":  {},
	"drupal":     {},
	"joomla":     {},
	"magento":    {},
	"windows":    {},
	"macos":      {},
	"osx":        {},
	"android":    {},
	"ios":        {},
}

func targetSWCompatible(targetSW string, fp *servicefingerprint.Fingerprint) bool {
	sw := strings.ToLower(strings.TrimSpace(targetSW))
	if sw == "" || sw == "*" || sw == "-" {
		return true
	}

	if _, isPlatform := unrelatedTargetSWs[sw]; !isPlatform {
		return true
	}

	if fingerprintMentions(fp, sw) {
		return true
	}

	return false
}

// targetSWWeak is true when the leaf names a concrete target_sw we could not
// token-match in the fingerprint (e.g. windows on a Linux nginx host).
func targetSWWeak(targetSW string, fp *servicefingerprint.Fingerprint) bool {
	sw := strings.ToLower(strings.TrimSpace(targetSW))
	if sw == "" || sw == "*" || sw == "-" {
		return false
	}

	if _, isPlatform := unrelatedTargetSWs[sw]; isPlatform {
		return false
	}

	return !fingerprintMentions(fp, sw)
}

func fingerprintMentions(fp *servicefingerprint.Fingerprint, needle string) bool {
	if fp == nil {
		return false
	}

	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return false
	}

	// Match the runtime/platform itself (python, nodejs), not libraries whose
	// product key merely contains the same token (python-requests).
	if cpemap.CanonicalProductKey(fp.Product) == needle {
		return true
	}

	if fp.Edition.Valid && hasToken(fp.Edition.String, needle) {
		return true
	}

	return false
}

func hasToken(s, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return false
	}

	for _, tok := range tokenSplitRE.Split(strings.ToLower(s), -1) {
		if tok == needle {
			return true
		}
	}

	return false
}
