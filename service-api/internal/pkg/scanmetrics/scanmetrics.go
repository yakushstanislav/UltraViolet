// Package scanmetrics exposes Prometheus instrumentation for the scan
// pipeline: in-flight gauge, run duration histogram, and stage-tagged error
// counters. Kept in one place so the worker, pipeline, and any future
// CLI runner share the same metric definitions.
package scanmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ScansInFlight tracks the number of scans currently executing on this
// worker.
var ScansInFlight = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "uv_scans_in_flight",
	Help: "Number of scans currently running on this worker",
})

// ScanDurationSeconds records the wall-clock duration of a finished scan,
// labelled by terminal status (done | failed | canceled | paused).
var ScanDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "uv_scan_duration_seconds",
	Help:    "Wall-clock duration of completed scans",
	Buckets: prometheus.ExponentialBuckets(1, 2, 14),
}, []string{"status"})

// ScanErrorsTotal counts non-terminal pipeline errors by stage so a stuck
// CVE matcher or DNS resolver is visible without scraping logs.
var ScanErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "uv_scan_errors_total",
	Help: "Errors encountered during scan execution, partitioned by stage",
}, []string{"stage"})

// QueueDepth reflects pending scan-job counts by status, refreshed by a
// background sampler in the worker.
var QueueDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "uv_queue_depth",
	Help: "Number of scans currently in each status (pending, running, paused)",
}, []string{"status"})

// CVESyncLastSuccessSeconds is the unix timestamp of the last successful CVE
// catalog sync (0 if none yet on this process).
var CVESyncLastSuccessSeconds = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "uv_cve_sync_last_success_seconds",
	Help: "Unix timestamp of the last successful CVE catalog sync",
})

// CVESyncErrorsTotal counts CVE catalog sync failures so an alert can fire
// when the worker stops syncing.
var CVESyncErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "uv_cve_sync_errors_total",
	Help: "Total number of CVE catalog sync errors observed by this worker",
})

// DNSLookupsTotal counts individual DNS queries by direction (forward |
// reverse), record type, and outcome (success | nxdomain | timeout | error) so
// an operator can tell "no DNS data" caused by a blocking upstream apart from
// the feature being disabled.
var DNSLookupsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "uv_dns_lookups_total",
	Help: "DNS queries issued during enrichment, partitioned by direction, type and outcome",
}, []string{"direction", "type", "outcome"})

// DNSLookupDurationSeconds records per-query wall-clock latency, labelled by
// direction, to surface a slow resolver pool.
var DNSLookupDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "uv_dns_lookup_duration_seconds",
	Help:    "Wall-clock latency of a single DNS query",
	Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
}, []string{"direction"})

// DNSRecordsPersistedTotal counts DNS records written to uv_dns_record by type,
// measuring how much enrichment data each scan actually yields.
var DNSRecordsPersistedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "uv_dns_records_persisted_total",
	Help: "DNS records upserted during enrichment, partitioned by record type",
}, []string{"type"})

// DNSHostsWithRecordsTotal counts hosts that received at least one DNS record,
// a direct measure of enrichment coverage across scans.
var DNSHostsWithRecordsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "uv_dns_hosts_with_records_total",
	Help: "Hosts that received at least one DNS record during enrichment",
})
