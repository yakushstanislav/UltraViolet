# Observability

The `observability` Compose profile bundles a Prometheus + Grafana
stack with pre-built dashboards. Use it for a one-command monitoring
deployment, or scrape the existing `/metrics` endpoints from your own
Prometheus.

## Activate the profile

```bash
cd service-env
docker compose --profile observability up -d
```

Adds two containers:

| Service | Port | Notes |
|---|---|---|
| `prometheus` | 9091 | Scrapes `uv-api:9090/metrics`. Config in `service-env/prometheus.yml`. |
| `grafana` | 3001 | Admin login: `admin` / `GRAFANA_ADMIN_PASSWORD`. |

The profile is additive — running it alongside the default stack does
not affect the other services. Stop with `docker compose --profile
observability down`.

## Grafana dashboards

Two dashboards ship in `service-env/grafana/dashboards/`:

| Dashboard | Panels |
|---|---|
| **UltraViolet API** | Request rate / errors / latency p50-p99 per route; WS connections; auth login outcomes; rate-limit fires. |
| **UltraViolet Scanner** | Active scans; completed scans by outcome; per-engine TCP dial rate; per-probe latency p50-p99; CVE worker tick health; retention rows pruned. |

Both dashboards use the standard Grafana variables (`$instance`,
`$prometheus_ds`) so you can attach them to an existing Grafana
instance — copy the JSON, import in your Grafana, point at your
Prometheus data source.

## Existing Prometheus

If you already run Prometheus, add the API and scanner scrape targets:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: uv-api
    metrics_path: /metrics
    static_configs:
      - targets: ['uv-api:9090']

  - job_name: uv-scanner
    metrics_path: /metrics
    static_configs:
      - targets: ['uv-scanner:9091']
```

`uv-scanner` does not enable the metrics endpoint by default in the
shipping compose — only `uv-api` does. Expose `9091:9091` in your
`docker-compose.override.yml` if you need it:

```yaml
services:
  uv-scanner:
    ports:
      - "127.0.0.1:9091:9091"
    environment:
      SCANNER_METRICS_PORT: "9091"
```

## Recommended alerts

A starter rule set:

```yaml
# uv-alerts.yml
groups:
- name: uv
  rules:
  - alert: UVAPI5xx
    expr: sum(rate(uv_http_requests_total{status=~"5.."}[5m]))
            / sum(rate(uv_http_requests_total[5m])) > 0.01
    for: 10m
    labels: {severity: warning}
    annotations:
      summary: "uv-api 5xx rate above 1%"

  - alert: UVScannerStuck
    expr: max_over_time(uv_scan_active[10m]) > 0
           and increase(uv_scan_completed_total[10m]) == 0
    for: 15m
    labels: {severity: warning}

  - alert: UVCVESyncStale
    expr: time() - max(uv_cve_sync_last_success_timestamp_seconds)
            > 2 * 6 * 3600
    for: 5m
    labels: {severity: info}
    annotations:
      summary: "NVD sync hasn't run in 2× the configured interval"

  - alert: UVPostgresDown
    expr: pg_up == 0
    for: 1m
    labels: {severity: critical}
```

`pg_up` requires `postgres_exporter`. The shipping observability
profile does not bundle it — add the exporter manually if you want
database-level alerts.

## Logging

`uv-api` and `uv-scanner` log structured JSON to stdout via `zap`.
Docker's default driver routes the lines to `journald` /
`docker logs`. For aggregation:

- **Loki** — point Promtail at `/var/lib/docker/containers/`.
- **Elasticsearch** — Fluent Bit with the Docker filter.
- **CloudWatch / Stackdriver** — the platform-specific Docker logging
  driver.

Either way, the lines parse as JSON; useful fields include `msg`,
`logger`, `request_id`, `scan_id`, `user_id`, `error`.

## Tracing

The shipping stack does not export OpenTelemetry traces today. The
hooks exist in `internal/pkg/logger` for future wiring — adding an
OTEL exporter is on the roadmap, not in this release.

## What to watch

The minimum healthy-stack signal list:

| Signal | Where | Healthy |
|---|---|---|
| `/readyz` on `uv-api` | HTTP | `200` |
| Postgres `pg_isready` | container healthcheck | `accepting connections` |
| `uv_scan_completed_total` increases over time | Prometheus | non-decreasing |
| `uv_cve_sync_runs_total{outcome="ok"}` increases on schedule | Prometheus | every `CVE_SYNC_INTERVAL` |
| `uv_ws_dropped_total` stays near zero | Prometheus | drops indicate slow clients |
| Disk usage on Postgres volume | host | trends bounded by retention envs |
