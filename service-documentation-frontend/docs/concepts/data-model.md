# Data Model

UltraViolet stores everything it discovers in a PostgreSQL database.
This page explains what each category of data represents and when it
is written — without diving into internal column names or indexes.

## Hosts

Every IP address that responds to at least one probe gets a **host
record**. It holds:

- The IP address and first/last seen timestamps.
- GeoIP metadata — country, city, latitude, longitude.
- ASN number and owning organisation.
- Reverse-DNS PTR hostname (when `RDNS_PTR_ENABLED=true`).

Hosts are never deleted between scans. `last_seen` is updated each
time a scan touches the IP.

## Services

A **service record** represents a single open port on a host
(`host + port + transport`). It holds:

- Port number and transport (TCP/UDP).
- Protocol identifier (`http`, `ssh`, `mysql`, …).
- The raw banner and its hash — used for delta change detection.
- A full-text search vector built from the banner.
- A risk score (0–100) and structured risk factors.

Multiple services per host are normal — a host with ports 22, 80, and
443 open has three service records.

## HTTP responses

When the HTTP probe succeeds, a **HTTP response record** is attached to
the service. It stores:

- Status code, server header, page title.
- Response body (up to `PROBE_MAX_BODY_BYTES`).
- Redirect chain.
- Parsed response headers.
- Detected technology stack (web server, CMS, frameworks).
- Favicon hash (Shodan-compatible mmh3).
- `robots.txt` and `security.txt` captures.

Both full-text and trigram indexes are built from the body, enabling
keyword and substring search across all collected pages.

## HTTP screenshots

When `HTTP_SCREENSHOT_ENABLED` is on (default), every successful HTTP probe enqueues a
row in `uv_http_screenshot_job` (CTE-protected against duplicate enqueue when
`body_sha256` is unchanged). The screenshot background worker claims pending
jobs (`FOR UPDATE SKIP LOCKED`), renders the page through the `chromium`
service over Chrome DevTools Protocol, and stores the resulting JPEG in
`uv_http_screenshot.thumbnail` (BYTEA, EXTERNAL storage). Failed jobs are
retried up to three times before transitioning to `failed` status.

Migrations introducing these tables:

| Migration | Tables |
|---|---|
| `1_initial_schema` | All core tables: hosts, services, HTTP/TLS/SSH/SMTP/DNS, CVE catalog, scans, alerts, screenshots, risk policy + protocol priors, risk snapshots. |

### Host attack-surface score

`uv_host` carries five risk columns persisted by the host risk service:

- `risk_score` (`SMALLINT`, 0..100) — the canonical bucket-aligned score.
- `probability` (`NUMERIC(5,4)`) — `P_host`, the unioned per-service
  compromise probability.
- `impact` (`NUMERIC(5,4)`) — `I_host`, derived from the untagged baseline +
  blast radius + lateral potential.
- `confidence` (`NUMERIC(4,3)`) — the mean of completeness / recency /
  signal-quality / tag-completeness meters.
- `risk_factors` (`JSONB`) — the explainable payload returned verbatim by
  the `risk-explain` endpoint (channels, impacts, confidence meters).

`uv_service` mirrors `risk_score` / `probability` / `confidence` /
`risk_factors` per service so dashboards and per-service explain views can
render the same shape.

Indexes: `uv_host_risk_score_idx`, `uv_host_risk_recent_idx`,
`uv_host_probability_idx`, `uv_host_confidence_idx`,
`uv_service_probability_idx`.

### Risk policy and per-protocol priors

`uv_risk_policy` is a named-policy table (singleton row `name = 'default'`
seeded by migration) holding the formula weights, decay half-lives and the
`k` coefficient. The `policy` service caches the row with TTL
`RISK_POLICY_CACHE_TTL`.

`uv_risk_protocol_prior` holds per-`(port_bucket, protocol_family)` baseline
exposure probabilities consumed by the `exposure` channel. The seven seeded
rows mirror the compiled-in `DefaultPriors()` table; operator overrides
require only an `UPDATE` and the cache refresh.

### Score timeline snapshots

`uv_host_risk_snapshot` and `uv_service_risk_snapshot` are append-only
timelines keyed on `(host_id, captured_at)` / `(service_id, captured_at)`.
Every host recompute emits one row via the `risksnapshot` repository so the
dashboard can render trend lines. The `risk_snapshot_retention` worker
prunes rows older than `RISK_EVENT_RETENTION_DAYS` (default 180d).

Indexes: `uv_host_risk_snapshot_host_recent_idx`,
`uv_host_risk_snapshot_captured_idx`, plus the matching pair on the service
table.

Pivot correlation partial indexes on `uv_tls_certificate` (fingerprint, JARM,
JA3S, JA4S) and `uv_http_response.favicon_hash`.

## TLS certificates

When a TLS handshake succeeds, the **certificate** is stored:

- Subject and issuer distinguished names.
- SHA-256 fingerprint of the certificate.
- Validity window.
- Subject Alternative Names (SANs).
- JARM fingerprint (when `PROBE_JARM_ENABLED=true`).
- JA3S / JA4S TLS server hashes.

The full certificate chain (leaf + intermediates) is preserved in
order, enabling issuer-based pivots.

## Service fingerprints

After probing, the scanner derives a **fingerprint** for every service:

- Product and version string (e.g. `nginx 1.25.3`, `OpenSSH 8.9`).
- Confidence level — `high` (exact parse), `medium` (heuristic),
  `low` (banner-only guess).
- Structured components such as TLS cipher suites, SSH algorithms, or
  HTTP framework signals.
- Auth-required flag when the service asked for credentials.

Fingerprints feed directly into CVE matching.

## Scans

A **scan record** tracks the lifecycle of one scan job:

- Target (CIDRs), port list, mode, strategy.
- Status (`pending → running → done / failed / canceled`).
- Progress cursor and statistics (total hosts, open ports, probes run).
- Delta summary (new, disappeared, changed service counts vs. the
  previous scan).

Scan schedules hold cron expressions and link to a scan template;
`uv-scanner` claims the next due schedule on each poll cycle.

## Delta and change events

When a scan completes, the engine compares each service against a
**snapshot** taken at the start of the scan. Differences are written as
**change events**:

- `new` — service was not present in the previous scan.
- `disappeared` — service was present before but not seen now.
- `changed` — service is present in both scans but the banner hash
  differs.

See [Delta](/delta/concept) for how to query and export these events.

### Snapshot and change-event table partitioning

`uv_service_snapshot` and `uv_service_change_event` are **range-partitioned by
`scan_id`**. Each scan that writes 50 M+ rows benefits from
partition pruning — per-scan queries touch only the matching partition instead
of the full table.

A **DEFAULT partition** (`uv_service_snapshot_default`,
`uv_service_change_event_default`) stores all rows until the operator creates
bounded partitions. Create one per scan after the scan completes:

```sql
-- Example: create a bounded partition for scan 42.
CREATE TABLE uv_service_snapshot_scan_42
    PARTITION OF uv_service_snapshot
    FOR VALUES FROM (42) TO (43);

-- Move existing rows out of the default partition.
WITH moved AS (
    DELETE FROM uv_service_snapshot_default
    WHERE scan_id = 42
    RETURNING *
)
INSERT INTO uv_service_snapshot_scan_42 SELECT * FROM moved;
```

To retire a completed scan and reclaim disk instantly:

```sql
ALTER TABLE uv_service_snapshot DETACH PARTITION uv_service_snapshot_scan_42;
DROP TABLE uv_service_snapshot_scan_42;
```

**Partitioned table keys:**

| Table | Primary key | Notes |
|---|---|---|
| `uv_service_snapshot` | `(scan_id, service_id)` | `id` column removed; `(scan_id, service_id)` was already the unique constraint. |
| `uv_service_change_event` | `(scan_id, id)` | `id` is a BIGINT with a sequence default; all existing `ORDER BY id` queries work unchanged. |

## CVE matches

Each fingerprinted service is matched against the local NVD mirror.
A **CVE match record** stores:

- The CVE identifier and its severity.
- Match reason and confidence level.
- EPSS probability and KEV flag (from enrichment runs).

See [CVE Overview](/cve/overview) for the full pipeline.

## DNS records

When `RDNS_PTR_ENABLED=true`, reverse-DNS PTR lookups are run after
each scan and stored as **DNS records**. When `FDNS_ENABLED=true`,
forward lookups (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV) are also stored.

`uv_dns_record` rows are unique on `(host_id, record_type, value)` and carry:

- `source` — provenance of the name: `ptr` (reverse DNS), `san` (TLS
  certificate SAN), `ct` (Certificate Transparency log), or `fcrdns`.
- `forward_confirmed` — `true` when a PTR hostname forward-resolves back to the
  scanned IP (forward-confirmed reverse DNS). The flag is sticky on conflict:
  once confirmed it stays confirmed.
- `first_seen` / `last_seen` / `captured_at` — observation window timestamps.

Zone-level `NS`/`SOA` records are queried once per apex domain and reused across
its subdomains via an in-process answer cache (`FDNS_CACHE_TTL`).

## Alerts

An **alert rule** pairs a saved search query with a notification
channel. When a scan produces results matching the query, an
**alert event** is written and the configured webhook / log is
triggered. See [Alert Rules](/alerts/rules).

## Identity and audit

- **Users** — username, hashed password, role (`viewer` / `operator` /
  `admin`), active flag, last login.
- **Refresh tokens** — issued on login, revoked on logout or password
  change.
- **Audit events** — every API call is logged with the user, method,
  path, HTTP status, source IP, and user-agent. Append-only.
  See [Audit Log](/admin/audit).
