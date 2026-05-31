// Package attackpath periodically rebuilds uv_host_relation (shared subnet,
// shared ASN, shared TLS fingerprint, shared favicon, shared JARM) and
// derives a centrality + pivot score per host into
// uv_host_attack_path_score. The risk scorer reads those scores to fuel
// the network_position probability channel.
package attackpath

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/riskmetrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/attackpath"
)

var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

// Config controls the worker cadence + caps.
type Config struct {
	Enabled             bool          `env:"ATTACKPATH_ENABLED"                env-default:"true"`
	Interval            time.Duration `env:"ATTACKPATH_INTERVAL"               env-default:"6h"`
	MaxNodes            int           `env:"ATTACKPATH_MAX_NODES"              env-default:"50000"`
	RelationMinStrength float64       `env:"ATTACKPATH_RELATION_MIN_STRENGTH"  env-default:"0.10"`
	CriticalScoreCutoff int           `env:"ATTACKPATH_CRITICAL_SCORE_CUTOFF"  env-default:"75"`
	// IncrementalEnabled flips between full rebuild (every pass walks
	// every host pair) and incremental rebuild (only edges involving a
	// host whose last_seen advanced since the previous tick are touched).
	// Full rebuild is correct but quadratic; incremental is cheaper but
	// stale data on un-touched hosts ages naturally. Default: incremental
	// after the first full pass.
	IncrementalEnabled bool `env:"ATTACKPATH_INCREMENTAL"            env-default:"true"`
}

// Job is the worker.Job implementation.
type Job struct {
	cfg                  Config
	pool                 *pgxpool.Pool
	attackPathRepository attackpath.Repository
	logger               *zap.SugaredLogger
	lastRunAt            time.Time
	lastSuccessAt        time.Time
}

// New builds a Job.
func New(cfg Config, pool *pgxpool.Pool, attackPathRepository attackpath.Repository, logger *zap.SugaredLogger) *Job {
	if cfg.Interval <= 0 {
		cfg.Interval = 6 * time.Hour
	}

	if cfg.MaxNodes <= 0 {
		cfg.MaxNodes = 50000
	}

	if cfg.RelationMinStrength <= 0 {
		cfg.RelationMinStrength = 0.10
	}

	if cfg.CriticalScoreCutoff <= 0 {
		cfg.CriticalScoreCutoff = 75
	}

	return &Job{
		cfg:                  cfg,
		pool:                 pool,
		attackPathRepository: attackPathRepository,
		logger:               logger,
	}
}

// Name implements worker.Job.
func (j *Job) Name() string { return "attack_path" }

// Tick implements worker.Job.
func (j *Job) Tick(ctx context.Context) (bool, error) {
	if !j.cfg.Enabled {
		return false, nil
	}

	now := time.Now().UTC()
	if !j.lastRunAt.IsZero() && now.Sub(j.lastRunAt) < j.cfg.Interval {
		return false, nil
	}

	j.lastRunAt = now

	tickStarted := time.Now()

	defer func() {
		riskmetrics.AttackPathComputeDurationSeconds.Observe(time.Since(tickStarted).Seconds())
	}()

	count, err := j.countHosts(ctx)
	if err != nil {
		return false, err
	}

	riskmetrics.AttackPathGraphNodes.Set(float64(count))

	if count > j.cfg.MaxNodes {
		j.logger.Warnw("Attack-path skipped: host count exceeds cap",
			zap.Int("hosts", count),
			zap.Int("cap", j.cfg.MaxNodes),
		)

		return false, nil
	}

	since := time.Time{}

	if j.cfg.IncrementalEnabled && !j.lastSuccessAt.IsZero() {
		// Subtract one interval as a safety margin — late-arriving
		// updates between the rebuild and the last_seen advance are
		// still captured.
		since = j.lastSuccessAt.Add(-j.cfg.Interval)
	}

	relations, err := j.buildRelations(ctx, since)
	if err != nil {
		return false, err
	}

	for _, relation := range relations {
		if relation.Strength < j.cfg.RelationMinStrength {
			continue
		}

		if upsertErr := j.attackPathRepository.UpsertRelation(ctx, relation); upsertErr != nil {
			j.logger.Warnw("Can't upsert host relation",
				zap.Uint64("src_host_id", relation.SrcHostID),
				zap.Uint64("dst_host_id", relation.DstHostID),
				zap.String("relation_type", relation.RelationType),
				zap.Error(upsertErr),
			)
		}
	}

	scores, err := j.computeScores(ctx, relations)
	if err != nil {
		return false, err
	}

	for _, score := range scores {
		if upsertErr := j.attackPathRepository.UpsertScore(ctx, score); upsertErr != nil {
			j.logger.Warnw("Can't upsert attack path score",
				zap.Uint64("host_id", score.HostID),
				zap.Error(upsertErr),
			)
		}
	}

	j.logger.Infow("Attack-path pass complete",
		zap.Int("relations", len(relations)),
		zap.Int("scored_hosts", len(scores)),
		zap.Bool("incremental", !since.IsZero()),
	)

	j.lastSuccessAt = now

	return true, nil
}

func (j *Job) countHosts(ctx context.Context) (int, error) {
	query, args, err := sq.Select("COUNT(*)::int").From("uv_host").ToSql()
	if err != nil {
		return 0, fmt.Errorf("can't build count hosts query: %w", err)
	}

	var count int

	if err := j.pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("can't count hosts: %w", pgkit.Handle(err))
	}

	return count, nil
}

// buildRelations issues one self-join aggregate per relation type and
// flattens the rows into Relation values. When `since` is non-zero the
// worker is in incremental mode: only host pairs where at least one side
// has last_seen >= since are emitted. Otherwise it is a full rebuild.
func (j *Job) buildRelations(ctx context.Context, since time.Time) ([]attackpath.Relation, error) {
	out := make([]attackpath.Relation, 0, 256)
	now := time.Now().UTC()

	subnetRows, err := j.querySharedSubnet(ctx, since)
	if err != nil {
		return nil, err
	}

	asnRows, err := j.querySharedASN(ctx, since)
	if err != nil {
		return nil, err
	}

	certRows, err := j.querySharedCert(ctx, since)
	if err != nil {
		return nil, err
	}

	faviconRows, err := j.querySharedFavicon(ctx, since)
	if err != nil {
		return nil, err
	}

	for _, pair := range subnetRows {
		out = append(out, attackpath.Relation{
			SrcHostID:    pair.src,
			DstHostID:    pair.dst,
			RelationType: "shared_subnet",
			Strength:     0.40,
			EvidenceJSON: jsonObject("subnet", pair.evidence),
			ComputedAt:   now,
		})
	}

	for _, pair := range asnRows {
		out = append(out, attackpath.Relation{
			SrcHostID:    pair.src,
			DstHostID:    pair.dst,
			RelationType: "shared_asn",
			Strength:     0.20,
			EvidenceJSON: jsonObject("asn", pair.evidence),
			ComputedAt:   now,
		})
	}

	for _, pair := range certRows {
		out = append(out, attackpath.Relation{
			SrcHostID:    pair.src,
			DstHostID:    pair.dst,
			RelationType: "shared_cert",
			Strength:     0.70,
			EvidenceJSON: jsonObject("fingerprint_sha256", pair.evidence),
			ComputedAt:   now,
		})
	}

	for _, pair := range faviconRows {
		out = append(out, attackpath.Relation{
			SrcHostID:    pair.src,
			DstHostID:    pair.dst,
			RelationType: "shared_favicon",
			Strength:     0.30,
			EvidenceJSON: jsonObject("favicon_hash", pair.evidence),
			ComputedAt:   now,
		})
	}

	return out, nil
}

type relationPair struct {
	src      uint64
	dst      uint64
	evidence string
}

func (j *Job) querySharedSubnet(ctx context.Context, since time.Time) ([]relationPair, error) {
	return j.queryRelationPairs(ctx,
		`SELECT a.id, b.id, host(network(set_masklen(a.ip, 24)))::text
		 FROM uv_host a
		 JOIN uv_host b ON a.id < b.id
		   AND family(a.ip) = 4
		   AND family(b.ip) = 4
		   AND set_masklen(a.ip, 24) = set_masklen(b.ip, 24)
		 WHERE (CAST($1 AS TIMESTAMP) IS NULL OR a.last_seen >= $1 OR b.last_seen >= $1)`,
		nullableTime(since))
}

func (j *Job) querySharedASN(ctx context.Context, since time.Time) ([]relationPair, error) {
	return j.queryRelationPairs(ctx,
		`SELECT a.id, b.id, a.asn::text
		 FROM uv_host a
		 JOIN uv_host b ON a.id < b.id
		   AND a.asn IS NOT NULL
		   AND a.asn = b.asn
		 WHERE (CAST($1 AS TIMESTAMP) IS NULL OR a.last_seen >= $1 OR b.last_seen >= $1)`,
		nullableTime(since))
}

func (j *Job) querySharedCert(ctx context.Context, since time.Time) ([]relationPair, error) {
	return j.queryRelationPairs(ctx,
		`SELECT DISTINCT sa.host_id, sb.host_id, ca.fingerprint_sha256
		 FROM uv_tls_certificate ca
		 JOIN uv_tls_certificate cb ON ca.fingerprint_sha256 = cb.fingerprint_sha256
		   AND ca.service_id < cb.service_id
		 JOIN uv_service sa ON sa.id = ca.service_id
		 JOIN uv_service sb ON sb.id = cb.service_id
		 JOIN uv_host ha ON ha.id = sa.host_id
		 JOIN uv_host hb ON hb.id = sb.host_id
		 WHERE ca.fingerprint_sha256 IS NOT NULL
		   AND sa.host_id <> sb.host_id
		   AND (CAST($1 AS TIMESTAMP) IS NULL OR ha.last_seen >= $1 OR hb.last_seen >= $1)`,
		nullableTime(since))
}

func (j *Job) querySharedFavicon(ctx context.Context, since time.Time) ([]relationPair, error) {
	return j.queryRelationPairs(ctx,
		`SELECT DISTINCT sa.host_id, sb.host_id, ha.favicon_hash::text
		 FROM uv_http_response ha
		 JOIN uv_http_response hb ON ha.favicon_hash = hb.favicon_hash
		   AND ha.service_id < hb.service_id
		 JOIN uv_service sa ON sa.id = ha.service_id
		 JOIN uv_service sb ON sb.id = hb.service_id
		 JOIN uv_host h1 ON h1.id = sa.host_id
		 JOIN uv_host h2 ON h2.id = sb.host_id
		 WHERE ha.favicon_hash IS NOT NULL
		   AND sa.host_id <> sb.host_id
		   AND (CAST($1 AS TIMESTAMP) IS NULL OR h1.last_seen >= $1 OR h2.last_seen >= $1)`,
		nullableTime(since))
}

// nullableTime threads the incremental cutoff through pgx as a true SQL
// NULL when the worker is in full-rebuild mode, so the WHERE clause
// short-circuits without a literal-comparison cost.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}

	return t
}

func (j *Job) queryRelationPairs(ctx context.Context, sqlText string, args ...any) ([]relationPair, error) {
	rows, err := j.pool.Query(ctx, sqlText, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query relation pairs: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make([]relationPair, 0, 64)

	for rows.Next() {
		var pair relationPair

		if err := rows.Scan(&pair.src, &pair.dst, &pair.evidence); err != nil {
			return nil, fmt.Errorf("can't scan relation pair: %w", pgkit.Handle(err))
		}

		if pair.src > pair.dst {
			pair.src, pair.dst = pair.dst, pair.src
		}

		out = append(out, pair)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate relation pairs: %w", err)
	}

	return out, nil
}

// computeScores derives a per-host centrality + pivot_score from the
// relation list. Centrality is the normalised degree (edges divided by the
// max-degree across the graph); pivot_score boosts hosts whose neighbours
// include CRITICAL-bucket peers.
func (j *Job) computeScores(ctx context.Context, relations []attackpath.Relation) ([]attackpath.Score, error) {
	degree := make(map[uint64]int, 64)
	neighbours := make(map[uint64]map[uint64]struct{}, 64)

	for _, relation := range relations {
		if relation.Strength < j.cfg.RelationMinStrength {
			continue
		}

		degree[relation.SrcHostID]++
		degree[relation.DstHostID]++

		if neighbours[relation.SrcHostID] == nil {
			neighbours[relation.SrcHostID] = make(map[uint64]struct{}, 4)
		}

		if neighbours[relation.DstHostID] == nil {
			neighbours[relation.DstHostID] = make(map[uint64]struct{}, 4)
		}

		neighbours[relation.SrcHostID][relation.DstHostID] = struct{}{}
		neighbours[relation.DstHostID][relation.SrcHostID] = struct{}{}
	}

	if len(degree) == 0 {
		return nil, nil
	}

	maxDegree := 1

	for _, d := range degree {
		if d > maxDegree {
			maxDegree = d
		}
	}

	criticalHosts, err := j.criticalHostIDs(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := make([]attackpath.Score, 0, len(degree))

	for hostID, d := range degree {
		centrality := float64(d) / float64(maxDegree)
		reachableCritical := 0

		for peer := range neighbours[hostID] {
			if _, ok := criticalHosts[peer]; ok {
				reachableCritical++
			}
		}

		pivot := centrality * (1.0 + 0.1*float64(reachableCritical))
		if pivot > 1 {
			pivot = 1
		}

		out = append(out, attackpath.Score{
			HostID:                 hostID,
			Centrality:             centrality,
			PivotScore:             pivot,
			ReachableCriticalCount: int32(reachableCritical),
			ComputedAt:             now,
		})
	}

	return out, nil
}

func (j *Job) criticalHostIDs(ctx context.Context) (map[uint64]struct{}, error) {
	query, args, err := sq.Select("id").
		From("uv_host").
		Where(squirrel.GtOrEq{"risk_score": j.cfg.CriticalScoreCutoff}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("can't build critical host query: %w", err)
	}

	rows, err := j.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("can't query critical hosts: %w", pgkit.Handle(err))
	}

	defer rows.Close()

	out := make(map[uint64]struct{}, 64)

	for rows.Next() {
		var id uint64

		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("can't scan critical host id: %w", pgkit.Handle(err))
		}

		out[id] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("can't iterate critical hosts: %w", err)
	}

	return out, nil
}

func jsonObject(key, value string) json.RawMessage {
	payload, err := json.Marshal(map[string]string{key: value})
	if err != nil {
		return json.RawMessage(`{}`)
	}

	return payload
}
