# Backup & Restore

`service-env/scripts/backup.sh` and `restore.sh` cover PostgreSQL. They
run `pg_dump` / `pg_restore` against the Postgres container without
touching the host's Postgres install. Backups land in
`service-env/backups/` as `uv-<ISO timestamp>.dump`.

## Taking a backup

```bash
cd service-env
./scripts/backup.sh
# → backups/uv-2026-05-19T12-00-00Z.dump
```

The script runs:

```bash
docker compose exec -T postgres \
  pg_dump -U ultraviolet -d ultraviolet -Fc \
  > backups/uv-$(date -u +%FT%H-%M-%SZ).dump
```

`-Fc` (custom format) is the format `pg_restore` expects.

A daily cron with 14-day retention:

```bash
0 3 * * * cd /opt/ultraviolet/service-env && \
  ./scripts/backup.sh && \
  find backups -name 'uv-*.dump' -mtime +14 -delete
```

`upgrade.sh` also runs `backup.sh` as its first step — every upgrade
leaves a fresh dump behind.

## Backup sidecar (optional)

The `backup` Compose profile runs a sidecar that calls `backup.sh` on
`BACKUP_INTERVAL_SECONDS` (default 21600 = 6 h):

```bash
docker compose --profile backup up -d
```

Use the sidecar when the host has no cron / systemd (e.g. on a
minimal Kubernetes node). Otherwise, the cron approach is simpler and
keeps the backup logic outside the runtime stack.

## What is in a backup

Everything in the `ultraviolet` database:

- Host inventory: hosts, services, HTTP responses, TLS certificates,
  service fingerprints, SSH/SMTP details, DNS records.
- Scan data: scan records, service snapshots, change events, delta
  summaries, scan schedules.
- User data: saved searches, alert rules, alert events.
- Identity: users, refresh tokens, audit log.
- CVE catalog: CVE records, CPE lists, sync state, CVE matches.

The backup is one consistent snapshot — `pg_dump` runs inside a single
transaction so no scan can split between rows.

## What is **not** in a backup

| Resource | Where it lives | How to back up |
|---|---|---|
| `.env` | `service-env/.env` | Copy out-of-band; contains `AUTH_JWT_SECRET`. |
| `secrets/postgres_password` | `service-env/secrets/` | Copy out-of-band. **Must** be paired with the dump on restore. |
| Docker volume (raw Postgres files) | `postgres-data` | Not needed for restore; the dump rebuilds the data. |
| GeoIP MMDB | `service-env/geoip/` | Refresh on demand; not state. |
| CVE seed dump | `service-env/catalog-seed/` | Re-derivable from the running catalog. |

The two things you must keep alongside the dump are `.env` (for the
JWT secret) and `secrets/postgres_password` (so the new instance can
authenticate to Postgres).

## Restoring

```bash
cd service-env
./scripts/restore.sh backups/uv-2026-05-19T12-00-00Z.dump
```

What the script does:

1. Stops `uv-api` and `uv-scanner` (so no writes race the restore).
2. Drops and recreates the `ultraviolet` database inside the running
   Postgres container.
3. Runs `pg_restore --no-owner --no-privileges` on the dump.
4. Restarts `uv-api` and `uv-scanner`.

`uv-api` runs migrations on startup; the dump is `--data-only`-free
(produced by `pg_dump -Fc` with full schema), so the migration runner
detects the version match and does nothing.

## Cross-host restore

To move the deployment to a new host:

```bash
# On the source
cd service-env
./scripts/backup.sh
tar czf uv-state.tar.gz .env secrets backups/uv-*.dump

# Copy uv-state.tar.gz to the destination

# On the destination, after `./install.sh`
tar xzf uv-state.tar.gz
./scripts/restore.sh backups/uv-2026-05-19T12-00-00Z.dump
```

`install.sh` had already generated fresh secrets — the `tar` restore
overwrites them with the originals so the dump matches. Keep the new
secrets only if you also rotate the Postgres password and re-encode
all access tokens (in practice: just keep the originals).

## Restoring against a different version

Restoring an older dump into a newer `uv-api`:

1. Restore the dump.
2. `uv-api` starts; the migration runner applies any new migrations on
   top of the restored data.

Restoring a newer dump into an older `uv-api`:

1. The schema in the dump has migrations the binary does not know about.
2. The migration runner refuses to start (`dirty schema` or
   `unknown version`).
3. Rolling forward to the matching `uv-api` is the only fix.

Always upgrade `uv-api` before restoring a newer dump on a fresh host.

## Sanity checks

```bash
# Check recent scans are present
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans?limit=5" | jq '.scans[].id'

# Check CVE catalog is populated
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/cve/sync-status" | jq '.providers[].cve_count'
```

If the API answers and the counts look right, the restore worked.
