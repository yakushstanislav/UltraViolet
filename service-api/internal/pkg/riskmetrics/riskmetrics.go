// Package riskmetrics exposes Prometheus collectors for the attack-surface
// risk pipeline: per-trigger recompute counter, snapshot append counter,
// attack-path graph gauges, and remediation backlog gauge. Kept in one place
// so workers and services share the same metric definitions.
package riskmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Recompute trigger labels — the recompute counter partitions by the
// caller so dashboards can tell "CVE match storm" from "ingest spike".
const (
	TriggerIngest   = "ingest"
	TriggerCVEMatch = "cve_match"
	TriggerPeriodic = "periodic"
	TriggerTagApply = "tag_apply"
	TriggerQueued   = "queued"
)

// RiskRecomputeTotal counts host-level recompute invocations, labelled by
// the trigger that fired them.
var RiskRecomputeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "uv_risk_recompute_total",
	Help: "Number of host-level risk recomputes, partitioned by trigger",
}, []string{"trigger"})

// RiskSnapshotAppendedTotal counts rows appended to uv_host_risk_snapshot.
var RiskSnapshotAppendedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "uv_risk_snapshot_appended_total",
	Help: "Number of rows appended to uv_host_risk_snapshot",
})

// AttackPathGraphNodes reflects the current host count used in the latest
// attack-path rebuild — useful as both an SLO signal and a capacity gauge.
var AttackPathGraphNodes = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "uv_attackpath_graph_nodes",
	Help: "Host count in the most recent attack-path computation",
})

// AttackPathComputeDurationSeconds records wall-clock time per attack-path
// rebuild — bucket widths cover the typical 0..600s range.
var AttackPathComputeDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "uv_attackpath_compute_duration_seconds",
	Help:    "Wall-clock duration of attack-path rebuilds",
	Buckets: prometheus.ExponentialBuckets(0.5, 2, 11),
})

// RemediationRecommendationsOpen is the gauge of open remediation rows
// across the whole inventory. Updated by the host risk aggregator after
// each refresh.
var RemediationRecommendationsOpen = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "uv_remediation_recommendations_open",
	Help: "Current count of remediation recommendations across the inventory",
})
