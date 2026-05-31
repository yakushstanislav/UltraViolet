# CVE & Risk Overview

UltraViolet ships a self-contained CVE pipeline. It mirrors NIST NVD,
enriches with CISA KEV and FIRST EPSS, matches services to CVE records
on a schedule, and contributes to the per-service risk score.

## Data sources

| Source | URL (default) | Refresh cadence |
|---|---|---|
| NVD CVE 2.0 | `https://services.nvd.nist.gov` | `CVE_SYNC_INTERVAL` (default 6 h) |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | `CVE_RISK_INTERVAL` (default 24 h) |
| FIRST EPSS | `https://epss.cyentia.com/epss_scores-current.csv.gz` | `CVE_RISK_INTERVAL` (default 24 h) |

All sources can be swapped or pointed at internal mirrors via the
`NVD_BASE_URL` / `CVE_KEV_URL` / `CVE_EPSS_URL` envs — useful for
air-gapped deployments that maintain their own mirror.

## Workers involved

| Worker | Triggers on |
|---|---|
| CVE sync | `CVE_SYNC_INTERVAL`. Pulls NVD deltas and updates the local catalog. |
| CVE match | `CVE_MATCH_INTERVAL`. Joins fingerprinted services to catalog entries. |
| CVE risk enrich | `CVE_RISK_INTERVAL`. Refreshes KEV and EPSS scores. |

All three workers run inside `uv-api` and respect its shutdown signal.

## Bootstrap

On a fresh database, the NVD mirror starts empty. Two paths to populate
it:

1. **Online bootstrap.** Leave `CVE_SYNC_ENABLED=true`. The worker
   reads `CVE_SYNC_BOOTSTRAP_FROM` (default `262800h` ≈ 30 years) and
   walks forward in `NVD_PAGE_SIZE` chunks. With an `NVD_API_KEY` and
   the default settings, a full pull takes a few hours.
2. **Seed catalog.** If you have a pre-built catalog dump (produced by
   `make cve-catalog-dump`), drop it at `CVE_CATALOG_SEED_FILE` and
   restart `uv-api`. The restore runs once on startup when the catalog
   is empty. See [CVE Catalog Seed](/deployment/cve-catalog-seed).

The offline-full archive bundles a ready-made seed so air-gapped
installs start with a populated catalog.

## Raw JSON storage

`CVE_SYNC_STORE_RAW_JSON=true` (default) keeps the original NVD JSON
payload for each CVE. Disable to shrink the catalog ~5×. The raw
payload is not used by the UI, so disabling it has no visible impact.

## Read endpoints

| Endpoint | Returns |
|---|---|
| `GET /v1/cve/sync-status` | Latest sync state (`last_sync`, `next_sync`, error). |
| `GET /v1/cves/{id}` | One CVE — CVSS, severity, EPSS, KEV, CPEs, references. |
| `GET /v1/services/{id}/cves` | Matches for a service, sorted by severity then EPSS then KEV. |

All three are readable by any authenticated role.

## What this pipeline does **not** do

- It does not actively exploit anything; it correlates discovered
  versions to published CVE records.
- It does not push to the host (no agent). The match is database-only.
- It does not "scan for CVEs" — the matcher reads the fingerprint that
  an earlier scan produced. If the fingerprint is missing or
  low-confidence, the match thresholds get stricter.
