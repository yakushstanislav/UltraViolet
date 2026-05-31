// Package cvesync periodically mirrors the NVD CVE 2.0 catalog into Postgres.
//
// On first run (bootstrap) the worker walks the full catalog. On subsequent
// runs it queries lastModStartDate=<state.last_mod_start> so only deltas are
// fetched. The cursor is advanced only after a successful pass.
package cvesync

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/nvd"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/scanmetrics"
	cvecatalog "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/catalog"
	cvesyncstate "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/cve/syncstate"
)

// nvdMaxWindow is the upper bound NVD allows for one
// lastModStartDate/lastModEndDate pair. We clamp to a slightly smaller value
// to stay safe across daylight-saving transitions.
const nvdMaxWindow = 110 * 24 * time.Hour

// Config controls the worker cadence.
type Config struct {
	Enabled  bool          `env:"CVE_SYNC_ENABLED"   env-default:"true"`
	Interval time.Duration `env:"CVE_SYNC_INTERVAL"  env-default:"6h"`
	// BootstrapFrom is how far back the first run reaches when mirroring
	// the NVD catalog. Default reaches to 1996-ish (≈30y) so the bootstrap
	// captures the whole catalogue: a CVE published in 2003 and never
	// modified afterwards still falls inside one of the 110-day windows
	// the worker iterates over. Shorter values are useful only for
	// development environments that don't want to wait for the full feed.
	BootstrapFrom time.Duration `env:"CVE_SYNC_BOOTSTRAP_FROM" env-default:"262800h"`
	// StoreRawJSON keeps the original NVD CVE blob in uv_cve.raw_json.
	// Turning it off shrinks the catalog by ~5x at the cost of losing the
	// ability to re-derive fields from upstream without a re-fetch.
	StoreRawJSON bool `env:"CVE_SYNC_STORE_RAW_JSON" env-default:"true"`
}

// Job mirrors the NVD catalog.
type Job struct {
	cfg         Config
	client      *nvd.Client
	catalog     cvecatalog.Repository
	state       cvesyncstate.Repository
	logger      *zap.SugaredLogger
	lastRunAt   time.Time
	lastTotalAt time.Time
}

// New builds a Job.
func New(
	cfg Config,
	client *nvd.Client,
	catalog cvecatalog.Repository,
	state cvesyncstate.Repository,
	logger *zap.SugaredLogger,
) *Job {
	return &Job{
		cfg:     cfg,
		client:  client,
		catalog: catalog,
		state:   state,
		logger:  logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "cve_sync" }

// Tick implements worker.Job. The job throttles itself to Interval so the
// runner can poll without doing real work on every call.
//
// Bootstrap is chunked one NVD window per Tick so a multi-window catch-up
// doesn't block sibling jobs (notably the scan queue) inside Runner.tickAll
// for the full bootstrap duration.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if !j.cfg.Enabled {
		return false, nil
	}

	if j.client == nil {
		return false, nil
	}

	now := time.Now().UTC()

	state, err := j.state.Get(ctx)
	if err != nil {
		return false, fmt.Errorf("can't read cve sync state: %w", err)
	}

	if !state.BootstrappedAt.Valid {
		return j.bootstrapStep(ctx, state.LastModStart, now)
	}

	interval := j.cfg.Interval
	if interval <= 0 {
		interval = 6 * time.Hour
	}

	if !j.lastRunAt.IsZero() && now.Sub(j.lastRunAt) < interval {
		return false, nil
	}

	j.lastRunAt = now

	return true, j.incremental(ctx, state.LastModStart, now)
}

// bootstrapStep fetches a single NVD window and advances the cursor. When the
// cursor catches up to now it marks the catalog as bootstrapped. Each step
// returns to the runner so other jobs get a tick in between windows.
func (j *Job) bootstrapStep(ctx context.Context, last sql.NullTime, now time.Time) (bool, error) {
	cursor := now.Add(-j.cfg.BootstrapFrom)
	if last.Valid {
		cursor = last.Time.UTC()
	}

	if !cursor.Before(now) {
		if err := j.state.MarkBootstrapped(ctx, now); err != nil {
			return false, err
		}

		j.logger.Infow("NVD bootstrap complete", zap.Time("to", now))

		return true, nil
	}

	end := cursor.Add(nvdMaxWindow)
	if end.After(now) {
		end = now
	}

	if err := j.fetchWindow(ctx, cursor, end); err != nil {
		scanmetrics.CVESyncErrorsTotal.Inc()

		return true, fmt.Errorf("bootstrap window failed: %w", err)
	}

	if err := j.state.SetLastModStart(ctx, end); err != nil {
		return true, err
	}

	scanmetrics.CVESyncLastSuccessSeconds.Set(float64(time.Now().Unix()))
	j.refreshEntries(ctx, now)

	return true, nil
}

func (j *Job) incremental(ctx context.Context, last sql.NullTime, now time.Time) error {
	from := now.Add(-24 * time.Hour)
	if last.Valid {
		from = last.Time.UTC()
	}

	if !from.Before(now) {
		return nil
	}

	if now.Sub(from) > nvdMaxWindow {
		from = now.Add(-nvdMaxWindow)
	}

	if err := j.fetchWindow(ctx, from, now); err != nil {
		scanmetrics.CVESyncErrorsTotal.Inc()

		return err
	}

	if err := j.state.SetLastModStart(ctx, now); err != nil {
		return err
	}

	scanmetrics.CVESyncLastSuccessSeconds.Set(float64(now.Unix()))
	j.refreshEntries(ctx, now)

	return nil
}

// refreshEntries updates uv_cve_sync_state.entries_done from a cheap COUNT(*)
// after every window, and re-pulls uv_cve_sync_state.entries_total from NVD
// at most once per hour so the dashboard progress bar can compute a real
// count-based fraction.
func (j *Job) refreshEntries(ctx context.Context, now time.Time) {
	done := -1

	if n, err := j.catalog.Count(ctx); err == nil {
		done = n
	} else {
		j.logger.Warnw("Can't count uv_cve", zap.Error(err))
	}

	total := -1

	if j.lastTotalAt.IsZero() || now.Sub(j.lastTotalAt) > time.Hour {
		if t, err := j.client.TotalCount(ctx); err == nil {
			total = t
			j.lastTotalAt = now
		} else {
			j.logger.Warnw("Can't read NVD totalResults", zap.Error(err))
		}
	}

	if done < 0 && total < 0 {
		return
	}

	if err := j.state.SetEntries(ctx, total, done); err != nil {
		j.logger.Warnw("Can't update CVE entries counters", zap.Error(err))
	}
}

func (j *Job) fetchWindow(ctx context.Context, from, to time.Time) error {
	query := nvd.Query{LastModStart: from, LastModEnd: to}

	j.logger.Infow("Fetching NVD window", zap.Time("from", from), zap.Time("to", to))

	count := 0

	err := j.client.Iterate(ctx, query, func(ctx context.Context, page nvd.Page) error {
		for _, vuln := range page.Vulnerabilities {
			if err := j.persist(ctx, vuln); err != nil {
				return err
			}

			count++
		}

		// Refresh entries_done after every NVD page so the dashboard
		// progress bar moves while a long bootstrap window is still in
		// flight. A bare COUNT(*) on uv_cve is cheap and NVD pages arrive
		// at most ~10/min without an API key, so this is not chatty.
		j.refreshEntries(ctx, time.Now().UTC())

		return nil
	})
	if err != nil {
		return err
	}

	j.logger.Infow("NVD window persisted", zap.Int("entries", count))

	return nil
}

func (j *Job) persist(ctx context.Context, vuln nvd.Vulnerability) error {
	cve := &cvecatalog.CVE{
		ID:     vuln.ID,
		Source: "nvd",
	}

	if vuln.Summary != "" {
		cve.Summary = sql.NullString{String: vuln.Summary, Valid: true}
	}

	if !vuln.PublishedAt.IsZero() {
		cve.PublishedAt = sql.NullTime{Time: vuln.PublishedAt, Valid: true}
	}

	if !vuln.LastModifiedAt.IsZero() {
		cve.LastModifiedAt = sql.NullTime{Time: vuln.LastModifiedAt, Valid: true}
	}

	if vuln.CVSSv3Score != 0 || vuln.CVSSv3Severity != "" {
		cve.CVSSv3Score = sql.NullFloat64{Float64: vuln.CVSSv3Score, Valid: true}
		cve.CVSSv3Severity = sql.NullString{String: vuln.CVSSv3Severity, Valid: vuln.CVSSv3Severity != ""}
		cve.CVSSv3Vector = sql.NullString{String: vuln.CVSSv3Vector, Valid: vuln.CVSSv3Vector != ""}
	}

	if vuln.CVSSv31Score != 0 || vuln.CVSSv31Severity != "" {
		cve.CVSSv31Score = sql.NullFloat64{Float64: vuln.CVSSv31Score, Valid: true}
		cve.CVSSv31Severity = sql.NullString{String: vuln.CVSSv31Severity, Valid: vuln.CVSSv31Severity != ""}
		cve.CVSSv31Vector = sql.NullString{String: vuln.CVSSv31Vector, Valid: vuln.CVSSv31Vector != ""}
	}

	if vuln.CVSSv40Score != 0 || vuln.CVSSv40Severity != "" {
		cve.CVSSv40Score = sql.NullFloat64{Float64: vuln.CVSSv40Score, Valid: true}
		cve.CVSSv40Severity = sql.NullString{String: vuln.CVSSv40Severity, Valid: vuln.CVSSv40Severity != ""}
		cve.CVSSv40Vector = sql.NullString{String: vuln.CVSSv40Vector, Valid: vuln.CVSSv40Vector != ""}
	}

	cve.References = vuln.References

	rawJSON := vuln.Raw
	if !j.cfg.StoreRawJSON {
		rawJSON = nil
	}

	if err := j.catalog.UpsertCVE(ctx, cve, rawJSON); err != nil {
		return fmt.Errorf("can't upsert cve: %w", err)
	}

	leaves := make([]cvecatalog.CPELeaf, 0, len(vuln.CPELeaves))

	for _, leaf := range vuln.CPELeaves {
		if leaf.Vendor == "" || leaf.Product == "" {
			continue
		}

		leaves = append(leaves, cvecatalog.CPELeaf{
			CVEID:                 vuln.ID,
			Vendor:                leaf.Vendor,
			Product:               leaf.Product,
			ExactVersion:          nullableString(leaf.ExactVersion),
			VersionStartIncluding: nullableString(leaf.VersionStartIncluding),
			VersionStartExcluding: nullableString(leaf.VersionStartExcluding),
			VersionEndIncluding:   nullableString(leaf.VersionEndIncluding),
			VersionEndExcluding:   nullableString(leaf.VersionEndExcluding),
			RawCPE:                leaf.Criteria,
			Vulnerable:            leaf.Vulnerable,
			TargetSW:              nullableString(leaf.TargetSW),
			TargetHW:              nullableString(leaf.TargetHW),
			Negate:                leaf.Negate,
		})
	}

	if err := j.catalog.ReplaceCPELeaves(ctx, vuln.ID, leaves); err != nil {
		return fmt.Errorf("can't replace cpe leaves: %w", err)
	}

	return nil
}

func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}

	return sql.NullString{String: s, Valid: true}
}
