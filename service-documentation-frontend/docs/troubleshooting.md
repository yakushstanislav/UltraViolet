# Troubleshooting

A grab bag of failures and how to triage them. When in doubt, start
with `docker compose ps`, `docker compose logs --since 10m`, and
`curl -sf http://localhost:8080/readyz`.

## `readyz` returns 503 with `database: migrating`

Migrations are running. They complete in seconds on small databases,
minutes on multi-GB CVE catalogs. Wait, then retry. If the same status
persists for more than a few minutes:

```bash
docker compose logs uv-api | grep migrate
```

A `dirty schema` line means an earlier migration crashed mid-flight.
Manual repair:

```bash
docker compose exec postgres psql -U ultraviolet -d ultraviolet \
  -c "SELECT version, dirty FROM schema_migrations;"
docker compose exec postgres psql -U ultraviolet -d ultraviolet \
  -c "UPDATE schema_migrations SET dirty=false WHERE version=<N>;"
docker compose restart uv-api
```

Use the `dirty=false` reset only after you've confirmed the migration
actually completed (inspect the affected tables). Otherwise restore
from backup.

## `uv-api` healthcheck flapping

The container restarts every minute, or `docker compose up` fails with
`dependency failed to start: container … uv-api … is unhealthy` while
scanner/frontend stay in `Created`. Likely causes, in order:

1. **First boot CVE seed restore.** On an empty database `uv-api` runs
   `pg_restore` from `catalog-seed/cve-catalog.dump` (~200 MB) *before*
   binding `:8080`. Healthchecks during that window fail unless
   `start_period` (default `300s` in compose) covers the restore. Watch:

   ```bash
   docker compose logs -f uv-api | grep -E 'Restoring CVE|Request completed.*readyz'
   ```

   Wait until `readyz` returns 200, or raise `start_period` in
   `docker-compose.override.yml` on slow disks.

2. **Postgres is unreachable.** `docker compose logs postgres` should
   show `ready to accept connections`. If not, the volume might be
   corrupt — restore from backup.
3. **`AUTH_JWT_SECRET` placeholder.** `uv-api` refuses to start when
   the placeholder is in `.env`. Replace it with `openssl rand -hex
   32`.
4. **`APP_ENV=production` with weak bootstrap creds.** Fix
   `AUTH_BOOTSTRAP_PASSWORD` or switch `APP_ENV=development` for
   triage.
5. **`POSTGRES_PASSWORD` mismatch** between `.env` and
   `secrets/postgres_password`. Re-run `install.sh` to re-sync or
   align them manually.

## Scanner never claims jobs

```bash
docker compose logs uv-scanner | grep -E 'claim|reclaim'
```

| Log line | Meaning |
|---|---|
| `ReclaimAllRunning: 0 rows` | Worker started cleanly, no orphans. |
| `claim: no rows ready` | No `PENDING` scan. Create one. |
| `claim: error` | Postgres connection error. Check `POSTGRES_*` envs and the network. |
| (silence) | The worker is paused or crashed. Check `kill -0 1` in the container; if missing, it crashed; check stdout. |

If you see `Reclaim` repeatedly without progress, the scan rows might
be stuck in `RUNNING` with an outdated `updated_at`. Drop
`SCANNER_RUNNING_TTL` temporarily to a few minutes so the watchdog
reclaims faster.

## Scan create returns 400 / UI shows an error immediately

The worker never runs because the API rejected the job. Check API logs:

```bash
docker compose logs uv-api | grep -E 'GeoIP|POST.*scans'
```

| Symptom | Fix |
|---|---|
| `No GeoIP country database configured` at API boot | Country-strategy scans need `service-env/geoip/*.mmdb` bind-mounted into **both** `uv-api` and `uv-scanner`. Run `make geoip-download`, then `docker compose up -d`. |
| UI: `scan_country_geoip_required` | Same as above — API could not open `/geoip/ip-to-country.mmdb`. |
| `scan_cidr_not_allowed` | Target is outside `SCAN_ALLOWED_CIDRS` in `.env`. |
| `scan_too_many_ports` | More than `SCAN_MAX_PORTS` (default 64) unique ports in `ports_expr`. |

## NVD sync stuck

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/cve/sync-status" | jq
```

`error` non-null and `last_sync` not advancing:

| Error | Fix |
|---|---|
| `403 Forbidden` from NVD | Missing or invalid `NVD_API_KEY` (or hitting the unauthenticated rate limit). Provision a key. |
| `429 Too Many Requests` | Lower request rate by raising `NVD_MIN_INTERVAL` to `6s`. |
| `context deadline exceeded` | Raise `NVD_TIMEOUT`. |
| `dial tcp: i/o timeout` | Network egress is blocked. Either open egress to `services.nvd.nist.gov` or set `CVE_SYNC_ENABLED=false` and use a [seed dump](/deployment/cve-catalog-seed). |

## CVE matches missing for a known service

The matcher needs three inputs to fire:

1. The service must have a detected product name (a fingerprint with a
   non-empty product field — verify on the host detail page).
2. The product name must have a canonicalisation entry that maps it to
   the NVD CPE vendor/product form. If the product is absent from the
   map, the matcher skips the service entirely.
3. A matching NVD CPE record must exist in the local catalog.

The most common cause is step 2: the product name used by UltraViolet
doesn't exactly match NVD's spelling. Add a canonicalisation entry
and trigger a re-match via `GET /v1/cve/sync-status` to confirm the
catalog is up-to-date.

## "no MMDB found" warning

`docker compose logs uv-scanner | grep geoip` shows the warning at
boot. Fix by:

1. Run `make geoip-download` (or `service-env/geoip/download-iplocate-mmdb.sh`).
2. Confirm `service-env/geoip/` now contains both `*.mmdb` files.
3. `docker compose restart uv-scanner` — the reader loads on boot, no
   hot-reload.

If you set `GEOIP_*_PATH` explicitly, check they point to readable
files inside the container (the bind-mount path, not the host path).

## Masscan/zmap fails with `Operation not permitted`

The container lacks `NET_RAW`. Verify:

```bash
docker compose exec uv-scanner sh -c 'capsh --print | grep cap_net_raw'
```

Add the capability in `docker-compose.override.yml`:

```yaml
services:
  uv-scanner:
    cap_add:
      - NET_RAW
      - NET_ADMIN
```

On managed Kubernetes / shared hosts the capability may be denied by
the platform. Switch to `native` engine in that case.

## RTSP snapshot returns `504 capture_timeout`

ffmpeg did not produce a frame within `RTSP_SNAPSHOT_TIMEOUT`. Common
causes:

- Wrong stream `path`. Try the ONVIF-assisted endpoint
  (`/v1/hosts/{ip}/onvif-rtsp-snapshot`).
- Credentials required but not provided.
- The stream uses UDP and the route blocks UDP — `ffmpeg -rtsp_transport
  tcp` is the default, but some devices refuse TCP.
- Camera is offline / NAT timeout.

Verify ffmpeg in the container:

```bash
docker compose exec uv-api ffmpeg -version
```

Missing? Install ffmpeg in your custom image (the shipping `uv-api`
image bundles it).

## WebSocket disconnects every minute

Your reverse proxy is dropping idle connections. Set:

```nginx
proxy_read_timeout 3600s;
```

(or longer) on the `location /` block that proxies to
`service-frontend`. See [Reverse Proxy](/deployment/reverse-proxy).

## "Origin not allowed" on WebSocket

Add the origin to `CORS_ALLOWED_ORIGINS`. The WS upgrade reads the
same env (plus glob entries for `127.*.*.*` on Vite dev ports).
Restart `uv-api` for the change to take effect.

## SPA shows a blank page after an upgrade

Hard refresh — the SPA fingerprints assets, but a stale `index.html`
in your CDN may reference deleted asset hashes. Bust the cache or
disable CDN caching of `index.html` (the JS/CSS hashes are
immutable, the HTML is not).

## Recreating the stack from scratch

When investigation costs more than rebuild:

```bash
cd service-env
docker compose down       # keep data
docker compose up -d      # restart
```

For a true clean slate (drops the database):

```bash
docker compose down -v    # drops postgres-data
./install.sh              # fresh secrets + first start
```

Restore from your latest backup afterwards.

## When you need to ask for help

Open an issue with:

1. UltraViolet version (`GET /v1/version`).
2. Compose file you're using (default / overrides).
3. The 50 lines around the error in `docker compose logs`.
4. What you tried.

Logs are the single best artefact — they include `request_id`,
`scan_id`, `user_id` where relevant, and they are structured JSON
that grep / jq can chew through fast.
