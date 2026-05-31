# Metrics

`uv-api` exposes Prometheus metrics on `METRICS_ADDR:METRICS_PORT`
(default `0.0.0.0:9090`). `uv-scanner` exposes its own set on
`SCANNER_METRICS_PORT` (typically `9091`).

The endpoints are **not** authenticated — they leak request rates and
schema cardinality but nothing sensitive. Bind them to a private
interface or to a firewalled port; only Prometheus should see them.

```bash
curl -s http://localhost:9090/metrics | head -40
```

## Key series

### HTTP server (`uv-api`)

| Metric | Labels | What it measures |
|---|---|---|
| `uv_http_requests_total` | `method`, `path`, `status` | Per-route request count. |
| `uv_http_request_duration_seconds` | `method`, `path` | Histogram. |
| `uv_http_inflight_requests` | — | Current in-flight count. |

### WebSocket (`uv-api`)

| Metric | Labels | What it measures |
|---|---|---|
| `uv_ws_connections` | `role` | Currently connected clients. |
| `uv_ws_events_sent_total` | `type` | Outbound event count per type. |
| `uv_ws_dropped_total` | — | Backpressure-dropped events. |

### Auth (`uv-api`)

| Metric | Labels | What it measures |
|---|---|---|
| `uv_auth_logins_total` | `outcome` (`ok`/`fail`) | Login attempts. |
| `uv_auth_refresh_total` | `outcome` | Refresh attempts. |
| `uv_auth_rate_limited_total` | `path` | Rate-limit fires. |

### Scanner (`uv-scanner`)

| Metric | Labels | What it measures |
|---|---|---|
| `uv_scan_active` | — | Currently running scans on this worker. |
| `uv_scan_completed_total` | `outcome` (`done`/`failed`/`canceled`) | Lifetime counter. |
| `uv_scan_duration_seconds` | — | Histogram of completed-scan durations. |
| `uv_portscan_dials_total` | `engine`, `result` | TCP dial outcomes per engine. |
| `uv_portscan_open_total` | `engine` | Discovered open ports. |
| `uv_probe_duration_seconds` | `probe` | Per-probe latency histogram. |
| `uv_probe_results_total` | `probe`, `outcome` | Probe outcomes (`matched`, `disclaimed`, `error`). |

### DNS enrichment (`uv-scanner`)

| Metric | Labels | What it measures |
|---|---|---|
| `uv_dns_lookups_total` | `direction` (`forward`/`reverse`), `type`, `outcome` (`success`/`nxdomain`/`timeout`/`error`) | Individual DNS queries. Separates "no data because disabled" from "upstream blocking". |
| `uv_dns_lookup_duration_seconds` | `direction` | Per-query latency histogram. |
| `uv_dns_records_persisted_total` | `type` | DNS records written to `uv_dns_record`. |
| `uv_dns_hosts_with_records_total` | — | Hosts that received ≥1 DNS record (coverage). |

### CVE workers

| Metric | Labels | What it measures |
|---|---|---|
| `uv_cve_sync_runs_total` | `outcome` | NVD sync ticks. |
| `uv_cve_sync_cve_count` | — | Catalog size. Gauge. |
| `uv_cve_match_services_total` | `outcome` | Match worker per-service outcomes. |
| `uv_cve_risk_enrich_runs_total` | `outcome` | KEV / EPSS refresh ticks. |

### Retention worker

| Metric | Labels | What it measures |
|---|---|---|
| `uv_retention_runs_total` | — | Tick count. |
| `uv_retention_rows_pruned_total` | `table` | Rows removed / nulled by table. |

### HTTP screenshot worker (`uv-scanner`)

| Metric | Labels | What it measures |
|---|---|---|
| `uv_http_screenshot_attempts_total` | `status` (`success` / `timeout` / `render_error` / `network_error` / `disabled`) | Per-outcome render attempts. |
| `uv_http_screenshot_duration_seconds` | — | Render wall-clock time histogram. |
| `uv_http_screenshot_size_bytes` | — | Compressed thumbnail size histogram. |
| `uv_http_screenshot_queue_depth` | `status` (`pending` / `running` / `failed`) | Job-queue depth gauge, sampled every 30 s. |

### Go runtime

Standard `go_*` and `process_*` metrics from `promhttp` are exposed —
heap, GC pauses, FD count, threads. Use them for capacity planning.

## Alerts (PromQL)

A few rules worth wiring on day one:

```
# API error rate above 1 %
sum(rate(uv_http_requests_total{status=~"5..|429"}[5m])) by (path)
  /
sum(rate(uv_http_requests_total[5m])) by (path)
  > 0.01

# Scanner not making progress
max_over_time(uv_scan_active[10m]) > 0
  unless changes(uv_scan_completed_total[10m]) > 0

# NVD sync hasn't run in 2× the configured interval
time() - uv_cve_sync_runs_total > 2 * 60 * 60 * 6
```

## Grafana

`service-env/grafana/` ships a Compose profile (`--profile
observability`) that bundles Prometheus + Grafana with two pre-built
dashboards:

- **UltraViolet API** — request rates, latencies, WS connections.
- **UltraViolet Scanner** — scan throughput, dial outcomes, probe
  latencies.

Run with:

```bash
cd service-env
docker compose --profile observability up -d
# Grafana on http://localhost:3001, admin/<GRAFANA_ADMIN_PASSWORD>
```

See [Observability](/deployment/observability) for the full setup.

## Attack-surface risk metrics

Exposed by `internal/pkg/riskmetrics`; populated by the host risk service,
the alert listener, the attack-path worker, and the snapshot retention
worker.

| Metric | Type | Labels | Purpose |
| --- | --- | --- | --- |
| `uv_risk_recompute_total` | counter | `trigger` ∈ `ingest`/`cve_match`/`periodic`/`tag_apply`/`unspecified` | Number of host-level recomputes per trigger. |
| `uv_risk_snapshot_appended_total` | counter | — | Rows appended to `uv_host_risk_snapshot`. |
| `uv_attackpath_graph_nodes` | gauge | — | Host count in the latest attack-path pass. |
| `uv_attackpath_compute_duration_seconds` | histogram | — | Wall-clock duration of attack-path rebuilds. |
| `uv_remediation_recommendations_open` | gauge | — | Current count of remediation recommendations across the inventory. |

## Cardinality notes

`path` on `uv_http_requests_total` uses the **route pattern**, not the
raw URI — so `/v1/users/{id}` is one label value regardless of the
actual id. This keeps the series count bounded.

The `probe` label on `uv_probe_*` is the protocol name (~100 values).
The `engine` label on `uv_portscan_*` has three values.
