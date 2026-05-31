# Architecture

UltraViolet is a four-container stack plus an optional documentation
container. Every component is stateless except PostgreSQL.

```
            ┌────────────────────────────────────────────────────────┐
            │                       Browser                          │
            └─────────────┬─────────────────────────┬────────────────┘
                          │ HTTPS (/, /api, /realtime)
                          ▼
                  ┌───────────────┐
                  │ service-front │  React 19 SPA, nginx 1.28
                  │   :3000 → :80 │  serves /, proxies /api → :8080
                  │               │  proxies /realtime → :8081
                  └──────┬────────┘
                         │
       ┌─────────────────┼─────────────────┐
       │                 │                 │
       ▼                 ▼                 ▼
  ┌─────────┐      ┌──────────┐      ┌──────────┐
  │ uv-api  │      │ uv-api   │      │ uv-api   │
  │ HTTP    │      │ WebSocket│      │ Metrics  │
  │ :8080   │      │  :8081   │      │  :9090   │
  └────┬────┘      └──────┬───┘      └──────────┘
       │  read/write       │ publish (LISTEN/NOTIFY)
       ▼                   │
  ┌───────────┐            │
  │ Postgres  │◀───────────┘
  │ :5432     │
  │ uv_*      │◀──── claim/update
  └─────▲─────┘           │
        │ read/write      │
        │                 │
        │           ┌─────┴──────┐
        └───────────┤ uv-scanner │  worker pool, no public ports
                    │            │  PORTSCAN_WORKERS, SCANNER_PROBE_WORKERS
                    └────────────┘
```

## Processes

### `uv-api` (`service-api/cmd/uv-api`)

Single Go binary that runs three HTTP-style servers in the same process:

| Server | Address | Purpose |
|---|---|---|
| HTTP API | `SERVER_ADDR:SERVER_PORT` (`:8080`) | REST under `/v1`, plus `/livez` and `/readyz`. |
| WebSocket | `REALTIME_ADDR:REALTIME_PORT` (`:8081`) | `/v1/ws` realtime events. |
| Metrics | `METRICS_ADDR:METRICS_PORT` (`:9090`) | Prometheus `/metrics`. |

The API also hosts background workers as goroutines:

- **NVD sync** — mirrors NIST NVD on a fixed interval (`CVE_SYNC_INTERVAL`).
- **CVE match** — joins fingerprinted services to CVE rows (`CVE_MATCH_INTERVAL`).
- **CVE risk enrich** — pulls CISA KEV and FIRST EPSS and updates the catalog (`CVE_RISK_INTERVAL`).
- **Alerts** — evaluates alert rules against fresh services, dispatches log/webhook.
- **Retention** — prunes old snapshots, HTTP bodies, change events, alert events (`RETENTION_TICK_EVERY`).
- **Scan schedule runner** — fires due schedules by inserting a new scan job.

### `uv-scanner`

Worker process that claims pending scans and runs the full scan
pipeline:

1. Resolves the CIDR into a target list (sequential or random sampling).
2. TCP port scan via the configured engine
   (native / masscan / zmap — see [Engines](/scanning/engines)).
3. UDP probe pass on `SCANNER_UDP_PROBE_PORTS`.
4. Protocol probes per discovered service
   (`SCANNER_PROBE_WORKERS` parallelism).
5. Reverse DNS, GeoIP, JARM, optional forward DNS / CT logs.
6. Writes hosts, services, HTTP responses, TLS certificates,
   fingerprints, and DNS records.
7. Snapshots the scan for delta computation.

A `SCANNER_RUNNING_TTL` watchdog reclaims orphaned running scans on
restart, so a SIGKILL or container restart never leaves a scan stuck.

### `service-frontend`

React 19 SPA built with Vite 8, served by nginx 1.28 in production. nginx
proxies `/api` to `uv-api:8080` and `/realtime` to `uv-api:8081`, so the
browser only ever talks to one origin. The nginx config is rendered at
container start via `envsubst` with `UV_BASE_PATH` — supports both root
mount and sub-path deployments (`/ultraviolet/`).

State is held in Redux Toolkit; WebSocket subscriptions live in
`features/Scans/scansSlice.ts`.

### PostgreSQL

PostgreSQL 16 (`postgres:16-alpine`). Extensions used:

- `pg_trgm` — trigram GIN indexes on banner, HTTP body, TLS subject/SANs,
  CVE ID, DNS records (substring search).
- `tsvector` columns + GIN indexes on banner and HTTP body (full-text
  search).

Migrations live in `service-api/deploy/migrations/`, applied at boot by
`golang-migrate`. See [Data Model](/concepts/data-model).

### `uv-documentation` (optional)

The site you are reading. Static HTML behind nginx, no runtime
dependencies. Activated with the `docs` Compose profile.

## Request paths

| Action | Path |
|---|---|
| Browser hits the UI | nginx → SPA static files |
| SPA calls REST | nginx `/api/*` → `uv-api:8080/v1/*` |
| SPA subscribes to realtime | nginx `/realtime` → `uv-api:8081/v1/ws` |
| Scanner claims jobs | `uv-scanner` → Postgres (`SELECT … FOR UPDATE SKIP LOCKED`) |
| Realtime events | Postgres `LISTEN/NOTIFY` channels → `uv-api` → WS clients |
| Metrics | Prometheus pulls `:9090/metrics` on `uv-api` (and `:9091` on `uv-scanner` when exposed) |

## Resource boundaries

- `uv-api` connection pool: `API_POSTGRES_MAX_CONNECTIONS` (default
  10 in prod compose, 40 in dev).
- `uv-scanner` connection pool: `SCANNER_POSTGRES_MAX_CONNECTIONS`
  (default 48).
- TCP fan-out per scanner: `PORTSCAN_WORKERS` (default 512),
  `PORTSCAN_RATE_PER_SEC` (default 5000),
  `PORTSCAN_MAX_DIALS_PER_IP` (default 64).
- Probe fan-out: `SCANNER_PROBE_WORKERS` (default 48).

Memory limits in `service-env/docker-compose.yml`:
`POSTGRES_MEMORY_LIMIT`, `UV_API_MEMORY_LIMIT`,
`UV_SCANNER_MEMORY_LIMIT`.
