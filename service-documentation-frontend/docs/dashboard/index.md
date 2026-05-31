# Dashboard

The Dashboard is the one-page overview of the estate. Open the UI and
this is the first view: aggregate counters, top tables, a world map, a
trends chart, and a risk breakdown.

## Layout

1. **Summary tiles** — total hosts, services, scans, CVEs.
2. **World map** — Leaflet map with a marker per country, sized by
   service count.
3. **Top** — top ports, top protocols, top risk factors.
4. **Trends** — 7-day rolling counters (new services, new CVEs, scans
   completed).
5. **Risk** — service `risk_score` histogram, host-level histogram, top risky
   services, and top risky **hosts** sorted by persisted `risk_score` (with
   optional top-factor label).
6. **Scans summary** — last N scans, by status, with quick links.

Every widget is backed by its own endpoint — the page composes them
client-side so a slow widget doesn't block the others.

On phones and large phones (≤640px), KPI tiles stay at the top; map, top
lists, trends, risk, and scans summary follow in a single column (same widgets
as desktop, stacked for narrow width).

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /v1/dashboard` | Summary tiles + small lists for the top widget. |
| `GET /v1/dashboard/map` | Country code → service count for the map. |
| `GET /v1/dashboard/top` | Top ports / protocols / risk factors (with `limit`). |
| `GET /v1/dashboard/trends` | Time series, default 7 d window. |
| `GET /v1/dashboard/risk` | Service + host risk histograms; top risky services and hosts. |
| `GET /v1/dashboard/scans/summary` | Latest scans + per-status counts. |

All endpoints are pre-aggregated server-side; do not replicate the
work with `/v1/search?limit=N` on a dashboard page.

## Summary tiles

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/dashboard" | jq
```

```json
{
  "totals": {
    "hosts":    14821,
    "services": 47102,
    "scans":    312,
    "cves":     271843
  },
  "recent_scans": [
    { "id": 412, "name": "Daily perimeter", "status": "DONE", "delta_summary": { "new": 14, "disappeared": 3, "changed": 7 } },
    …
  ]
}
```

The summary uses cheap `count(*)` queries with btree-friendly
predicates — none of the widgets do a full table scan.

## Map

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/dashboard/map" | jq
```

```json
{
  "countries": [
    { "country_code": "NL", "host_count": 1241, "service_count": 4280, "latitude": 52.13, "longitude": 5.29 },
    { "country_code": "DE", "host_count": 980,  "service_count": 3110, "latitude": 51.16, "longitude": 10.45 },
    …
  ]
}
```

The Leaflet map clusters markers at low zoom levels; click-through
runs a search filtered to that country.

## Top widget

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/dashboard/top?limit=10" | jq
```

```json
{
  "top_ports":      [ { "port": 443, "count": 8421 }, … ],
  "top_protocols":  [ { "protocol": "https", "count": 8230 }, … ],
  "top_risk":       [ { "factor": "outdated_version", "count": 1812 }, … ]
}
```

`limit` is bounded server-side (≤ 50).

## Trends

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/dashboard/trends?days=7" | jq
```

Daily buckets in UTC; the response includes new services, new CVEs,
and the count of completed scans per day. The chart on the page is a
stacked area built from these series.

## Risk

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/dashboard/risk" | jq
```

Returns histogram buckets (`0-19`, `20-39`, `40-59`, `60-79`,
`80-100`) plus the top contributing factors with their counts. See
[Risk Scoring](/cve/risk-scoring) for what feeds the score.

## Scans summary

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/dashboard/scans/summary" | jq
```

```json
{
  "by_status": {
    "PENDING":  2,
    "RUNNING":  1,
    "DONE":     303,
    "FAILED":   4,
    "CANCELED": 2
  },
  "latest":    [ … ]
}
```

The page renders this as a single-line status strip plus the table of
the last few scans.

## Performance characteristics

Every dashboard query runs in milliseconds against a populated
database. All widgets hit dedicated indexes — the most expensive is the
risk distribution, which scans risk scores for all services but is
backed by a composite index that keeps it fast even at 50 M rows.

## Roles

All dashboard endpoints — any authenticated role.
