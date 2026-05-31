# CVE Matching

The CVE matcher runs on a schedule and joins each fingerprinted service
to CVE rows in the local catalog. It only processes services whose
fingerprint changed since the last evaluation, so steady-state runs are
fast.

## How matches are produced

For each service with a detected product:

1. The product name is canonicalised to the CPE vendor/product form used
   by NVD. Products that have no canonicalisation entry are skipped.
2. Candidate CVEs are retrieved for that vendor/product pair.
3. The service version (if captured) is intersected with each CVE's
   version ranges. Three cases arise:
   - **Exact version match** — `match_reason = product_version`,
     `confidence = high`.
   - **Version-less CPE** (`*` in the NVD version range) — matched on
     product alone; confidence is derived from the fingerprint quality.
   - **Banner / server-header hit** — when no version range exists at
     all; `confidence = low`. The matcher only falls back here for CVEs
     with no version data whatsoever.

## `match_reason` values

| Value | When |
|---|---|
| `product_version` | Exact CPE version range intersected with the captured version. |
| `product` | CVE has no version range; matched on product alone. |
| `banner` | Substring match on the raw banner for CVEs with no version range. |
| `server_header` | Substring match on the HTTP Server header. |
| `fingerprint` | Derived heuristics (TLS subject, favicon hash, etc.). |

## `confidence` values

| Value | Typical setup |
|---|---|
| `high` | Exact version match, high-confidence fingerprint. |
| `medium` | Version-less or low-confidence fingerprint with a strong backup signal. |
| `low` | Banner-only match, or the fingerprint itself was low-confidence. |

The UI shows the value as a chip on each CVE row. The search bar
accepts `confidence:high` for filtering.

## Configuration

```bash
CVE_MATCH_ENABLED=true
CVE_MATCH_INTERVAL=15m
CVE_MATCH_BATCH=500           # services per tick
CVE_MATCH_CONCURRENCY=8       # parallelism inside the tick
```

Tuning hints:

- A large bootstrap leaves many services in the queue. Raise
  `CVE_MATCH_BATCH` and `CVE_MATCH_CONCURRENCY` for the first day to
  burn through the backlog, then dial back.
- The matcher is database-bound. If it is consistently slow, verify that
  the PostgreSQL instance has enough connections and RAM for plan caching.

## Resetting matches

To force a full re-evaluation of all services (e.g. after fixing a
product canonicalisation entry):

```bash
docker compose exec postgres psql -U ultraviolet -d ultraviolet -c \
  "TRUNCATE uv_service_cve, uv_service_match_state"
```

The matcher re-evaluates all services on its next tick.

## Roles

`GET /v1/services/{id}/cves` — any authenticated role. Match records
are written only by the matcher worker, not through the API.
