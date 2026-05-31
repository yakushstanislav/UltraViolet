# CVE Synchronisation

The CVE sync worker mirrors NIST NVD into the local catalog. Every tick
it pulls new and modified entries and updates the local CVE and CPE
records.

## Configuration

```bash
CVE_SYNC_ENABLED=true            # master switch
CVE_SYNC_INTERVAL=6h             # cadence
CVE_SYNC_BOOTSTRAP_FROM=262800h  # how far back to walk on a fresh DB
CVE_SYNC_STORE_RAW_JSON=true     # keep raw NVD JSON
NVD_BASE_URL=https://services.nvd.nist.gov
NVD_API_KEY=                     # optional, raises rate limit 5→50 req/30s
NVD_PAGE_SIZE=2000               # max per NVD docs
NVD_TIMEOUT=30s                  # per-request HTTP timeout
NVD_USER_AGENT=UltraViolet/0.1
NVD_MAX_RETRIES=5
NVD_MIN_INTERVAL=0s              # gap between requests (set to ~6s without an API key)
```

`NVD_MIN_INTERVAL` is the simplest way to stay under NVD's rate limit
without an API key. With a key, leave it at `0s`.

## What gets synced

For each CVE the worker records:

- CVE identifier, published date, last modified date.
- English description (full-text indexed for search).
- CVSS v2 and v3 base scores and severity.
- CPE applicability list (vendor + product + version range per row).
- EPSS score and KEV flag — populated by the risk-enrich worker on a
  separate schedule.
- Original NVD JSON payload when `CVE_SYNC_STORE_RAW_JSON=true`.

## Status endpoint

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/cve/sync-status" | jq

# {
#   "providers": [
#     {
#       "name":      "nvd",
#       "last_sync": "2026-05-17T06:14:11Z",
#       "next_sync": "2026-05-17T12:14:11Z",
#       "cve_count": 271843,
#       "error":     null
#     }
#   ]
# }
```

Open during a bootstrap to watch progress; useful for capacity planning
(the count grows ~50 CVEs/day in steady state).

## Tuning

| Symptom | Try |
|---|---|
| Bootstrap is slow | Provision `NVD_API_KEY`, leave `NVD_MIN_INTERVAL=0s`. |
| HTTP errors from NVD | Raise `NVD_MAX_RETRIES`; check worker logs for the NVD HTTP code. |
| Disk pressure from raw JSON | Set `CVE_SYNC_STORE_RAW_JSON=false`. |
| Air-gapped install | Drop a seed dump, see [CVE Catalog Seed](/deployment/cve-catalog-seed). Set `CVE_SYNC_ENABLED=false`. |

## Disabling

`CVE_SYNC_ENABLED=false` stops the sync worker. The match worker keeps
running against the static catalog you provided (e.g. a seed dump).
Existing matches stay; new CVEs are not added until you re-enable sync
or re-seed.

## Mirrors

`NVD_BASE_URL` can point at any host that exposes the NVD 2.0 schema.
Several vendors offer internal mirrors — useful in air-gapped
enterprises that route NVD fetches through a corporate proxy.
