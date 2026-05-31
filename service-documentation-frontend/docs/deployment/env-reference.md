# Environment Reference

Every env-var consumed by `uv-api` and `uv-scanner`, grouped by area.
The source of truth is `service-env/.env.example`; this page mirrors it
in a more readable form. Update both when you add a variable.

## Stack metadata

| Variable | Default | Used by | Notes |
|---|---|---|---|
| `COMPOSE_FILE` | `docker-compose.yml:docker-compose.dev.yml` | Compose | Stripped from release archives. |
| `UV_REGISTRY` | `docker.io/ultraviolet` | Compose | Image prefix. |
| `UV_VERSION` | `dev` | Compose | Image tag. |

## GeoIP

| Variable | Default | Used by | Notes |
|---|---|---|---|
| `GEOIP_CITY_PATH` | (empty) | scanner | Auto-detect in `./geoip` and `/geoip` if blank. |
| `GEOIP_ASN_PATH` | (empty) | scanner | Same auto-detect. |

## HTTP API listeners

| Variable | Default | Used by | Notes |
|---|---|---|---|
| `SERVER_ADDR` | `0.0.0.0` | uv-api | REST bind. |
| `SERVER_PORT` | `8080` | uv-api | |
| `METRICS_ADDR` | `0.0.0.0` | uv-api | Prometheus bind. |
| `METRICS_PORT` | `9090` | uv-api | |
| `REALTIME_ADDR` | `0.0.0.0` | uv-api | WebSocket bind. |
| `REALTIME_PORT` | `8081` | uv-api | |
| `REALTIME_WS_ALLOWED_ROLES` | `viewer,operator,admin` | uv-api | Roles permitted on `/v1/ws`. |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000,…` | uv-api | Comma-separated. Narrow in production. |
| `VITE_API_URL` | `/api` | frontend build | Build-time only. |
| `VITE_REALTIME_URL` | `/realtime` | frontend build | Build-time only. |
| `NODE_IMAGE`, `NGINX_IMAGE` | (defaults) | frontend build | Override base images when GHCR pulls fail. |

## Postgres / PgBouncer / Auth

`uv-api` and `uv-scanner` connect to **PgBouncer**, not directly to
PostgreSQL. The PostgreSQL address exposed to the application is always
`pgbouncer:5432`. The variables below configure the application-side
connection pool (client connections to PgBouncer); PgBouncer's own pool
toward PostgreSQL is fixed at 40 real connections in `docker-compose.yml`.

| Variable | Default | Used by | Notes |
|---|---|---|---|
| `POSTGRES_PASSWORD` | (generated) | api + scanner + pgbouncer | Must equal `secrets/postgres_password`. |
| `POSTGRES_MAX_CONNECTIONS` | `10` (api) / `20` (scanner) | api + scanner | Client connections **to PgBouncer**, not to PostgreSQL. PgBouncer multiplexes these into 40 real PG connections. |
| `POSTGRES_MEMORY_LIMIT` | `6g` | compose | PostgreSQL container cap. Sized for `shared_buffers=2GB` in the bundled `postgresql.conf`. |
| `PGBOUNCER_MEMORY_LIMIT` | `128m` | compose | PgBouncer container cap. |
| `AUTH_JWT_SECRET` | (placeholder; replace!) | uv-api | HS256 signing key. |
| `AUTH_ACCESS_TTL` | `15m` | uv-api | Access token TTL. |
| `AUTH_REFRESH_TTL` | `168h` | uv-api | Refresh token TTL. |
| `AUTH_BOOTSTRAP_USERNAME` | `admin` | uv-api | First-user creation. |
| `AUTH_BOOTSTRAP_PASSWORD` | `admin` | uv-api | Must change before non-dev. |
| `AUTH_BOOTSTRAP_ROLE` | `admin` | uv-api | |
| `AUTH_RATE_LIMIT_RPS` | `1` | uv-api | Per-IP rate limit on auth endpoints. |
| `AUTH_RATE_LIMIT_BURST` | `5` | uv-api | |
| `APP_ENV` | `production` | uv-api | `production` enforces password strength + rejects `admin/admin`. |
| `APP_DEMO_MODE` | `false` | uv-api | Set `true` to block user creation, deletion, and password resets. Intended for public demo instances. |
| `AUDIT_TRUST_PROXY_HEADERS` | `false` | uv-api | Trust XFF for audit + rate limit. Only enable behind a real proxy. |

## OIDC SSO (optional)

| Variable | Default | Notes |
|---|---|---|
| `OIDC_ENABLED` | `false` | Master switch. |
| `OIDC_ISSUER_URL` | (empty) | OpenID Connect issuer. |
| `OIDC_CLIENT_ID` | (empty) | |
| `OIDC_CLIENT_SECRET` | (empty) | |
| `OIDC_REDIRECT_URL` | (empty) | |
| `OIDC_SCOPE` | `openid email profile` | |

## Scan policy

| Variable | Default | Notes |
|---|---|---|
| `SCAN_ALLOWED_CIDRS` | `0.0.0.0/0,::/0` | Allowlist. Tighten in production. |
| `SCAN_MAX_HOSTS` | `4096` | Per-scan cap. |
| `SCAN_MAX_PORTS` | `65535` | Per-scan cap. |

## Scanner runtime

| Variable | Default | Notes |
|---|---|---|
| `SCANNER_RUNNING_TTL` | `1h` | Watchdog for orphaned `RUNNING` rows. |
| `SCANNER_WORKER_POLL_INTERVAL` | `1s` | Hot-path claim cadence. |
| `SCANNER_BACKGROUND_POLL_INTERVAL` | `30s` | Slow workers: cvesync, schedule, retention. |
| `SCANNER_PROGRESS_INTERVAL` | `1s` | Progress cursor flush. |
| `API_POSTGRES_MAX_CONNECTIONS` | 10 (prod) / 40 (dev) | uv-api pool. |
| `SCANNER_POSTGRES_MAX_CONNECTIONS` | `48` | uv-scanner pool. |
| `SCANNER_PROBE_WORKERS` | `48` | Per-service probe parallelism. |

## TCP discovery (native engine)

| Variable | Default | Notes |
|---|---|---|
| `PORTSCAN_WORKERS` | `512` | Concurrency of TCP dials. |
| `PORTSCAN_TIMEOUT` | `2s` | Per-dial timeout. |
| `PORTSCAN_RATE_PER_SEC` | `5000` | Token-bucket rate. |
| `PORTSCAN_MAX_DIALS_PER_IP` | `64` | `0` disables. |

## Probe stack

| Variable | Default | Notes |
|---|---|---|
| `PROBE_TIMEOUT` | `10s` | Per-probe budget for HTTP/S, TLS, and specialised probes. |
| `PROBE_BANNER_TIMEOUT` | `2s` | Timeout for the generic banner probe (unknown ports). Shorter than `PROBE_TIMEOUT` to avoid blocking workers on filtered/unresponsive ports. |
| `PROBE_MAX_BODY_BYTES` | `262144` | Banner/body cap. |
| `PROBE_BACKEND` | `native` | `native` or `stdlib`. |
| `PROBE_JARM_ENABLED` | `true` | JARM TLS fingerprinting. |
| `SCANNER_UDP_PROBE_PORTS` | `53,161,123,5353,623` | UDP probe pass after TCP. Empty disables. |

## DNS enrichment

Reverse (PTR) and forward DNS share one resolver pool (round-robin, retries,
TCP fallback on truncation), so neither depends on the container's
`/etc/resolv.conf`. Leave `RDNS_RESOLVERS` blank to fall back to the system
resolver for reverse DNS in closed networks.

| Variable | Default | Notes |
|---|---|---|
| `RDNS_PTR_ENABLED` | `true` | PTR lookup after TCP pass. |
| `RDNS_GO_PROCESSES` | `8` | Parallel PTR workers (0 = 8). |
| `RDNS_TIMEOUT` | `2m` | Batch timeout. |
| `RDNS_PER_LOOKUP_TIMEOUT` | `5s` | Per-IP lookup deadline. |
| `RDNS_RESOLVERS` | `1.1.1.1:53,8.8.8.8:53` | Round-robin pool. Empty = system resolver. |
| `RDNS_RETRIES` | `1` | Extra attempts on transient failure (pool mode). |
| `RDNS_CACHE_TTL` | `5m` | In-process PTR cache ceiling. `0` = off. |
| `FDNS_ENABLED` | `true` | Forward DNS enrichment (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV). |
| `FDNS_THREADS` | `8` | Parallel hostname workers. |
| `FDNS_TIMEOUT` | `2m` | Batch timeout. |
| `FDNS_RESOLVERS` | `1.1.1.1:53,8.8.8.8:53` | Round-robin pool. |
| `FDNS_QUERY_TIMEOUT` | `3s` | Per-query deadline. |
| `FDNS_RETRIES` | `1` | Extra attempts on transient failure. |
| `FDNS_CACHE_TTL` | `5m` | In-process answer cache ceiling (NS/SOA reuse). `0` = off. |

## Masscan engine

| Variable | Default | Notes |
|---|---|---|
| `MASSCAN_BINARY` | `masscan` | Binary path. |
| `MASSCAN_RATE` | `3000` | Packets per second. |
| `MASSCAN_RETRIES` | `2` | Extra SYN sends per port. |
| `MASSCAN_WAIT_SECONDS` | `30` | Cool-down before parsing. |
| `MASSCAN_INTERFACE` | (auto) | |
| `MASSCAN_UNPRIVILEGED` | `false` | Set `true` to drop SYN cap (degrades). |

## Zmap engine

| Variable | Default | Notes |
|---|---|---|
| `ZMAP_BINARY` | `zmap` | |
| `ZMAP_RATE` | `1000` | Packets per second. |
| `ZMAP_COOLDOWN_SECONDS` | `8` | |
| `ZMAP_INTERFACE` | (auto) | |

## Retention

| Variable | Default | Notes |
|---|---|---|
| `RETENTION_TICK_EVERY` | `6h` | Worker tick cadence. |
| `RETENTION_SNAPSHOTS` | `720h` | Service snapshot window. |
| `RETENTION_HTTP_BODY` | `720h` | HTTP body nullification window. |
| `RETENTION_HTTP_SCREENSHOTS` | `720h` | HTTP thumbnail deletion window. |
| `RETENTION_CHANGE_EVENTS` | `2160h` | Delta events. |
| `RETENTION_ALERT_EVENTS` | `720h` | Alert events. |

## NVD / CVE sync

| Variable | Default | Notes |
|---|---|---|
| `NVD_BASE_URL` | `https://services.nvd.nist.gov` | Override for internal mirrors. |
| `NVD_API_KEY` | (empty) | Raises rate limit 5 → 50 req/30s. |
| `NVD_PAGE_SIZE` | `2000` | NVD max. |
| `NVD_TIMEOUT` | `30s` | |
| `NVD_USER_AGENT` | `UltraViolet/0.1` | |
| `NVD_MAX_RETRIES` | `5` | |
| `NVD_MIN_INTERVAL` | `0s` | Set ~6s without an API key. |
| `CVE_SYNC_ENABLED` | `true` | |
| `CVE_SYNC_INTERVAL` | `6h` | |
| `CVE_SYNC_BOOTSTRAP_FROM` | `262800h` | How far back to walk on a fresh DB. |
| `CVE_SYNC_STORE_RAW_JSON` | `true` | Disable to shrink catalog ~5×. |

## CVE matching

| Variable | Default | Notes |
|---|---|---|
| `CVE_MATCH_ENABLED` | `true` | |
| `CVE_MATCH_INTERVAL` | `15m` | |
| `CVE_MATCH_BATCH` | `500` | Services per tick. |
| `CVE_MATCH_CONCURRENCY` | `8` | |
| `CVE_MATCH_MIN_CONFIDENCE` | `0` | Drop matches below this confidence score (0–100). Set to `40` to suppress versionless (conf=30) and heavily backport-penalised findings while keeping all normal versioned matches. |

## CVE risk enrichment

| Variable | Default | Notes |
|---|---|---|
| `CVE_RISK_ENABLED` | `true` | |
| `CVE_RISK_INTERVAL` | `24h` | |
| `CVE_KEV_URL` | (CISA URL) | KEV feed. |
| `CVE_EPSS_URL` | (Cyentia URL) | EPSS feed (.csv.gz). |
| `CVE_RISK_TIMEOUT` | `60s` | |
| `CVE_RISK_USER_AGENT` | `UltraViolet/0.1` | |

## CVE catalog seed

| Variable | Default | Notes |
|---|---|---|
| `CVE_CATALOG_SEED_FILE` | (empty) | Path to a `pg_dump -Fc` of `uv_cve` + `uv_cve_cpe`. |
| `CVE_CATALOG_SEED_DIR` | (empty) | Directory containing `*.dump`; newest wins. |

## RTSP snapshot

| Variable | Default | Notes |
|---|---|---|
| `RTSP_SNAPSHOT_ENABLED` | `true` | |
| `RTSP_SNAPSHOT_FFMPEG` | `ffmpeg` | |
| `RTSP_SNAPSHOT_TIMEOUT` | `12s` | |
| `RTSP_SNAPSHOT_MAX_CONCURRENT` | `4` | |

## HTTP screenshot

Requires the `chromium` service (started with the default compose stack).
The render worker lives in `uv-scanner`; the `GET /v1/hosts/{ip}/services/{service_id}/screenshot`
endpoint lives in `uv-api`.

| Variable | Default | Notes |
|---|---|---|
| `HTTP_SCREENSHOT_ENABLED` | `true` | Master switch. Worker skips claims when off. |
| `HTTP_SCREENSHOT_CHROMIUM_URL` | `http://chromium:9222` | Chrome DevTools HTTP endpoint. |
| `HTTP_SCREENSHOT_TIMEOUT` | `15s` | Full render budget per page. |
| `HTTP_SCREENSHOT_NAVIGATE_TIMEOUT` | `10s` | Wait for `Page.loadEventFired`. |
| `HTTP_SCREENSHOT_MAX_CONCURRENT` | `4` | Parallel CDP sessions. |
| `HTTP_SCREENSHOT_VIEWPORT_WIDTH` | `1280` | Browser viewport width. |
| `HTTP_SCREENSHOT_VIEWPORT_HEIGHT` | `800` | Browser viewport height. |
| `HTTP_SCREENSHOT_THUMBNAIL_WIDTH` | `640` | Output JPEG width; sets `deviceScaleFactor = thumb / viewport` for browser-side downsample. |
| `HTTP_SCREENSHOT_JPEG_QUALITY` | `80` | 1-100. |
| `SCREENSHOT_WORKER_BATCH` | `8` | Jobs claimed per tick. |
| `CHROMIUM_MEMORY_LIMIT` | `1g` | Memory cap on the `chromium` container. |

## ONVIF

| Variable | Default | Notes |
|---|---|---|
| `ONVIF_COMMAND_ENABLED` | `true` | |
| `ONVIF_COMMAND_TIMEOUT` | `15s` | |
| `ONVIF_COMMAND_MAX_CONCURRENT` | `8` | |
| `ONVIF_COMMAND_RATE_LIMIT_RPS` | `5` | `0` disables. |
| `ONVIF_COMMAND_RATE_LIMIT_BURST` | `20` | |
| `ONVIF_RESPONSE_CACHE_TTL` | `0s` | Anonymous read-only cache. |
| `ONVIF_RTSP_SNAPSHOT_ENABLED` | `true` | |
| `ONVIF_LAB_CREDENTIAL_PROBE_ENABLED` | `false` | Lab-only feature. |
| `ONVIF_LAB_CREDENTIALS_FILE` | (empty) | Optional file; otherwise embedded list. |
| `ONVIF_LAB_CREDENTIAL_MAX_PAIRS` | `200` | Clamped 1–500. |
| `ONVIF_LAB_PER_ATTEMPT_TIMEOUT` | `6s` | |
| `ONVIF_LAB_INTER_ATTEMPT_DELAY` | `100ms` | |

## CT logs / RDAP

| Variable | Default | Notes |
|---|---|---|
| `CTLOGS_ENABLED` | `false` | crt.sh discovery (scanner pipeline). |
| `CTLOGS_BASE_URL` | `https://crt.sh` | |
| `CTLOGS_TIMEOUT` | `15s` | |
| `CTLOGS_LIMIT` | `50` | |
| `CTLOGS_USER_AGENT` | `UltraViolet/0.1` | HTTP User-Agent for crt.sh requests. |
| `CTLOGS_MAX_RETRIES` | `5` | Retry budget for crt.sh (exponential backoff). |
| `RDAP_ENABLED` | `false` | WHOIS enrichment. |

## Backup / observability sidecars

| Variable | Default | Notes |
|---|---|---|
| `BACKUP_INTERVAL_SECONDS` | `21600` | Only when `--profile backup`. |
| `GRAFANA_ADMIN_PASSWORD` | `admin` | Only when `--profile observability`. |

## Host risk aggregation (`uv-scanner`)

| Variable | Default | Notes |
|---|---|---|
| `HOST_RISK_ENABLED` | `true` | Periodic host score catch-up worker. |
| `HOST_RISK_INTERVAL` | `15m` | Tick interval; also used after inline ingest aggregation. |
| `HOST_RISK_BATCH` | `500` | Hosts processed per worker tick. |
| `HOST_RISK_THRESHOLD` | `65` | Service `risk_score` counted as high-risk for broad-exposure bonus. |
| `RISK_POLICY_CACHE_TTL` | `60s` | TTL for the in-process `uv_risk_policy` + protocol-prior cache. |
| `RISK_SNAPSHOT_ENABLED` | `true` | Snapshot retention worker. Phase 1 appends snapshots inline on every host recompute; this gate controls only the pruner. |
| `RISK_SNAPSHOT_INTERVAL` | `1h` | Tick interval for the snapshot retention worker. |
| `RISK_SNAPSHOT_MIN_DELTA` | `2` | Reserved for Phase 3 dedup ("snapshot only if &#124;Δscore&#124; ≥ this or 24h passed"). |
| `RISK_EVENT_RETENTION_DAYS` | `180` | Maximum snapshot age before the retention worker prunes the row. |
| `RISK_RECOMPUTE_QUEUE_ENABLED` | `true` | When `true`, CVE-matcher and ingest recompute requests go through the in-process debounced queue instead of running synchronously. Disable to fall back to the legacy hot-path. |
| `RISK_RECOMPUTE_DEBOUNCE` | `2s` | Coalescing window for the recompute queue: repeated host-level recompute requests inside this window collapse into one. |
| `RISK_RECOMPUTE_WORKERS` | `4` | Worker-pool size that drains the recompute queue. |
| `ATTACKPATH_ENABLED` | `true` | Periodic worker that rebuilds `uv_host_relation` + `uv_host_attack_path_score`. |
| `ATTACKPATH_INTERVAL` | `6h` | Tick interval. |
| `ATTACKPATH_INCREMENTAL` | `true` | When `true`, after the first full pass the worker only re-evaluates host pairs touched since the previous tick (`last_seen >= cutoff`). Disable to force a full rebuild every tick. |
| `ATTACKPATH_MAX_NODES` | `50000` | Host count past which the worker logs a warn and skips the pass. |
| `ATTACKPATH_RELATION_MIN_STRENGTH` | `0.10` | Edges weaker than this are dropped before persistence. |
| `ATTACKPATH_CRITICAL_SCORE_CUTOFF` | `75` | `risk_score >= cutoff` neighbours feed the pivot-score boost. |

## Reminder

When you add a new env-var, append a row here in the same commit. The
[`Documentation (Mandatory)`](#) rule in `CLAUDE.md` enforces this.
