# Docker Compose

The shipping deployment is a single `docker-compose.yml` in
`service-env/`. The compose file describes the production stack;
`docker-compose.dev.yml` is the development overlay that builds images
from source and bumps a few connection-pool sizes.

## Services

| Service | Image | Ports (host:container) | Notes |
|---|---|---|---|
| `postgres` | `postgres:16-alpine` | (internal only) | Volume: `postgres-data`. Bundled `postgres/postgresql.conf` (includes `listen_addresses='*'` so other containers can reach Postgres via Docker networking). Memory: `POSTGRES_MEMORY_LIMIT` (default `6g`). |
| `pgbouncer` | `edoburu/pgbouncer:v1.25.1-p0` | (internal only) | Connection pooler (transaction mode). `uv-api` and `uv-scanner` connect here, not directly to Postgres. Password from `POSTGRES_PASSWORD` in `.env` (synced by `install.sh`). Memory: `PGBOUNCER_MEMORY_LIMIT` (default `128m`). |
| `uv-api` | `${UV_REGISTRY}/uv-api:${UV_VERSION}` | `8080:8080`, `8081:8081`, `9090:9090` | REST + WS + metrics. Bind-mount: `./geoip` → `/geoip` (country-strategy validation). `cap_drop: ALL`. |
| `uv-scanner` | `${UV_REGISTRY}/uv-scanner:${UV_VERSION}` | — | Worker. Bind-mount: `./geoip` → `/geoip` (host enrichment + country scans). `cap_drop: ALL` + `cap_add: NET_RAW, NET_ADMIN` when masscan/zmap engines are needed. |
| `service-frontend` | `${UV_REGISTRY}/uv-frontend:${UV_VERSION}` | `3000:8080` | nginx serving the SPA; proxies `/api/` → `uv-api:8080` and `/realtime/` → `uv-api:8081`. |
| `uv-documentation` (opt-in) | `${UV_REGISTRY}/uv-documentation:${UV_VERSION}` | `3001:80` | This documentation site. Activated with `--profile docs`. |
| `chromium` | `chromedp/headless-shell:latest` | (internal `:9222`) | Chrome DevTools Protocol backend for HTTP screenshots. Memory: `CHROMIUM_MEMORY_LIMIT` (default `1g`). |

## PgBouncer connection pool

`uv-scanner` connects through `pgbouncer` in **transaction mode**. `uv-api` connects directly to `postgres` so schema migrations and advisory locks work (pgbouncer transaction mode breaks `golang-migrate`).
The pool holds 40 real PostgreSQL connections
(`PGBOUNCER_DEFAULT_POOL_SIZE`), shared between `uv-api` (10 client
connections) and `uv-scanner` (20 client connections). This decouples the
application connection count from the PostgreSQL `max_connections` limit
(set to 100 in `postgresql.conf`).

| Env | Default | Notes |
|---|---|---|
| `PGBOUNCER_DEFAULT_POOL_SIZE` (set in compose) | `40` | Real PG connections. |
| `PGBOUNCER_MAX_CLIENT_CONN` (set in compose) | `500` | Max concurrent client connections across all pools. |
| `PGBOUNCER_MEMORY_LIMIT` | `128m` | Container memory cap. |

The `postgres-backup` service connects **directly to `postgres`** (not
`pgbouncer`) because `pg_dump` requires a non-transactional session that
pgbouncer's transaction mode cannot provide.

## Profiles

| Profile | Adds |
|---|---|
| (default, none) | `postgres`, `pgbouncer`, `chromium`, `uv-api`, `uv-scanner`, `service-frontend`. |
| `docs` | `uv-documentation`. |
| `observability` | Prometheus + Grafana. See [Observability](/deployment/observability). |
| `backup` | A sidecar that runs `backup.sh` on `BACKUP_INTERVAL_SECONDS`. |

Activate:

```bash
docker compose --profile docs up -d
docker compose --profile observability up -d
docker compose --profile backup up -d
```

Profiles compose — `--profile docs --profile observability` brings both
up.

## Healthchecks

| Service | Check |
|---|---|
| `postgres` | `pg_isready -U ultraviolet` every 5 s. |
| `pgbouncer` | `nc -z 127.0.0.1 5432` every 10 s (TCP listen only — avoids auth login lines in pgbouncer logs). Postgres health + app SQL cover backend reachability. |
| `uv-api` | `curl -sf http://localhost:8080/readyz` every 10 s; `start_period: 300s` while migrations and optional CVE seed restore run (HTTP is not listening until restore finishes). |
| `uv-scanner` | `kill -0 1` every 30 s (PID 1 is the worker; BusyBox `pgrep -x` does not match `/ServiceAPI/uv-scanner`). |
| `service-frontend` | `wget -q http://127.0.0.1:8080/` (nginx in-container port; use IPv4 — Alpine resolves `localhost` to `::1`). |
| `uv-documentation` | `curl -sf http://localhost:80/`. |

`depends_on` uses `condition: service_healthy` so the SPA does not
start before the API answers; the API does not start before Postgres
finishes migrations.

## Secrets

`secrets/postgres_password` is mounted into the Postgres container as
`/run/secrets/postgres_password` (read by the official entrypoint via
`POSTGRES_PASSWORD_FILE`). `uv-api` and `uv-scanner` read the same
value from `POSTGRES_PASSWORD` in the env file — `install.sh` keeps
both in sync.

`AUTH_JWT_SECRET` lives in `.env` directly. See [Secrets](/deployment/secrets).

## Memory limits

`docker-compose.yml` reads these envs with sensible defaults; raise them
when the host has the budget:

| Env | Default | Container |
|---|---|---|
| `POSTGRES_MEMORY_LIMIT` | `6g` | `postgres` |
| `PGBOUNCER_MEMORY_LIMIT` | `128m` | `pgbouncer` |
| `UV_API_MEMORY_LIMIT` | `2g` | `uv-api` |
| `UV_SCANNER_MEMORY_LIMIT` | `3g` | `uv-scanner` |
| `CHROMIUM_MEMORY_LIMIT` | `1g` | `chromium` |

The frontend and documentation containers do not declare limits — they
sit comfortably under 64 MiB.

The `POSTGRES_MEMORY_LIMIT` default is `6g` (raised from `2g`) to match
the `shared_buffers = 2GB` + `maintenance_work_mem = 512MB` + working
memory in the bundled `postgresql.conf`. On an 8 GB host, `uv-api` +
`uv-scanner` + `pgbouncer` share the remaining 2 GB.

## Image registry and version

```bash
UV_REGISTRY=docker.io/ultraviolet
UV_VERSION=v0.1.0
```

For air-gapped installs the registry never gets called; `install.sh`
loads tarred images from `images/` instead — see
[Offline Install](/deployment/offline-install).

## Networking

A single user-defined bridge network. The services reach each other by
service name (`uv-api`, `postgres`, …). Only the explicit `ports:`
mappings expose anything to the host; everything else stays inside the
network.

The frontend nginx is the only HTTP entry point in a typical
deployment. The API ports (`8080`, `8081`, `9090`) are not strictly
necessary at the host level — bind them to `127.0.0.1` in
`docker-compose.override.yml` if your reverse proxy lives on the same
host:

```yaml
services:
  uv-api:
    ports:
      - "127.0.0.1:8080:8080"
      - "127.0.0.1:8081:8081"
      - "127.0.0.1:9090:9090"
```

## Dev overlay (`docker-compose.dev.yml`)

- Builds `uv-api`, `uv-scanner`, `service-frontend`,
  `uv-documentation` from source instead of pulling from the registry.
- Raises `API_POSTGRES_MAX_CONNECTIONS` from 10 → 40 for snappier dev
  loops.
- Enables verbose logging (`LOGGER_DEBUG=true`).

Activated by default through `COMPOSE_FILE=docker-compose.yml:docker-compose.dev.yml`
in `.env.example`. Release archives strip that line — they pull from
the registry.

## Start, stop, inspect

```bash
docker compose up -d                # start
docker compose ps                   # status
docker compose logs -f uv-api       # tail one service
docker compose logs --since 10m     # everything in the last 10 min
docker compose down                 # stop without removing volumes
docker compose down -v              # stop and remove volumes (DROPS DATA)
```
