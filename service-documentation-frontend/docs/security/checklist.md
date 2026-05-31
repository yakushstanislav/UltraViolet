# Production Checklist

Before opening UltraViolet to other operators, walk this list once.
It is the same set referenced in the repository's top-level `README.md`,
spelled out in operational terms.

## Identity and secrets

- [ ] **Rotate the bootstrap user.** Create a personal admin account
      via `POST /v1/users`. Log out, log in as the new admin, delete or
      disable the bootstrap row.
- [ ] **`APP_ENV=production`.** With this set, `admin / admin` and
      short passwords are rejected at startup.
- [ ] **`AUTH_BOOTSTRAP_PASSWORD`** is a passphrase ≥ 8 chars (12+
      recommended). Treat it as a one-time secret — change it again
      after rotation.
- [ ] **`AUTH_JWT_SECRET`** is replaced with a fresh `openssl rand
      -hex 32` value. The placeholder string from `.env.example`
      triggers `install.sh` to abort, but check anyway.
- [ ] **`secrets/postgres_password`** contains 32 random bytes,
      generated locally, never committed.
- [ ] **`AUTH_ACCESS_TTL`** ≤ 15 min. Shorter values make revocation
      cheap; the SPA handles refresh transparently.
- [ ] **`AUTH_REFRESH_TTL`** matches your session policy
      (7 d default).
- [ ] **`AUTH_RATE_LIMIT_RPS` / `AUTH_RATE_LIMIT_BURST`** raised only
      if you sit behind a NAT/proxy that collapses real users.

## Network exposure

- [ ] **HTTPS reverse proxy in front of the frontend container.**
      Example: `service-env/examples/nginx-tls.conf`.
- [ ] **`uv-api` ports bound to `127.0.0.1`** in
      `docker-compose.override.yml` (only the outer proxy reaches
      `:8080` / `:8081` / `:9090`).
- [ ] **`CORS_ALLOWED_ORIGINS`** lists only your public origin. Drop
      the `localhost` entries.
- [ ] **`AUDIT_TRUST_PROXY_HEADERS=true`** when behind a real proxy.
      Leave `false` otherwise.
- [ ] **Prometheus port (`9090`) is not public.** Bind to loopback or
      a private interface.

## Scan policy

- [ ] **`SCAN_ALLOWED_CIDRS`** lists only the ranges you own or have
      written authorisation to scan. The default `0.0.0.0/0,::/0` is
      meant for lab use only.
- [ ] **`SCAN_MAX_HOSTS`** and **`SCAN_MAX_PORTS`** match your
      operational guard rails — small enough to bound accidental
      blast radius.
- [ ] **Masscan / zmap engines** require `cap_add: NET_RAW,
      NET_ADMIN` on the scanner container. Grant these only on hosts
      you own outright; on shared / multi-tenant hosts, restrict to
      the `native` engine.

## Feature gates

- [ ] **`ONVIF_LAB_CREDENTIAL_PROBE_ENABLED=false`** outside lab
      environments. The probe is destructive against hardened devices.
- [ ] **`RTSP_SNAPSHOT_ENABLED`** and **`ONVIF_COMMAND_ENABLED`**
      reflect your appetite. Disable when not used.
- [ ] **`CTLOGS_ENABLED` / `RDAP_ENABLED` / `FDNS_ENABLED`** flip
      these on deliberately — they make outbound network calls that
      may be visible to third parties.

## Data and retention

- [ ] **Backups on a schedule.** Cron `scripts/backup.sh` daily,
      keep 14 days.
- [ ] **Off-host copy** of `.env` and `secrets/` — a backup with
      no JWT secret is unusable.
- [ ] **`RETENTION_*` envs** match your storage budget. The defaults
      (30 / 30 / 90 / 30 d) are conservative; lower them on small
      hosts.
- [ ] **GeoIP refresh** on a monthly cron
      (`scripts/geoip-refresh.sh`).

## CVE pipeline

- [ ] **`NVD_API_KEY`** if you intend to bootstrap online. With a
      key, the catalog walk completes in hours; without one, days.
- [ ] **`CVE_SYNC_ENABLED=false`** with a static seed when running
      air-gapped.
- [ ] **Seed dump** in `catalog-seed/` for fresh deployments so the
      catalog starts populated.

## Monitoring

- [ ] **Prometheus scraping** `uv-api:9090/metrics`. The default
      Grafana dashboards from `service-env/grafana/` work out of the
      box.
- [ ] **`/readyz` health check** wired to the load balancer (it
      returns `503` during migrations, which is what you want).
- [ ] **Alerts** on the API 5xx rate, the scanner activity, and the
      NVD sync recency (see [Observability](/deployment/observability)).

## Hardening the host

- [ ] **Docker rootless** or a non-root daemon user where possible.
- [ ] **`cap_drop: ALL`** is already set on every shipping container.
      Do not add capabilities unless masscan/zmap require them.
- [ ] **`no-new-privileges: true`** is already set on the frontend
      and documentation containers. Mirror it on others if you
      customise the compose.

## Audit and traceability

- [ ] **Pipe `docker logs uv-api` to a SIEM**. The JSON lines
      include `request_id`, `user_id`, `scan_id`.
- [ ] **`/v1/audit`** queried periodically (or pulled into the SIEM)
      so admin actions are reviewable.
- [ ] **Document who has admin.** Use the user-management UI to
      enumerate; the audit log will tell you what they did.

## Threat model gotchas

- The cleartext access token is **bearer auth** — anyone with the
  token can act as the user until `exp`. Cookie-style auth with `HttpOnly`
  is not built in. Use a short TTL and HTTPS-only deployment.
- The RTSP snapshot path captures images from streams. Network admins
  who see UltraViolet traffic but don't see the user's intent may
  interpret the captures as unauthorised. Document the operator role.
- The lab credential probe is functionally a default-password brute
  force. Treat it the same way you'd treat any authorised credential
  testing — written approval, lab scope, monitoring.

## When in doubt

Read [Responsible Scanning](/security/responsible-scanning) and the
upstream code. The repo's `CLAUDE.md` documents the conventions used
during code review; the `Documentation (Mandatory)` rule there means
every release has a current doc-set.
