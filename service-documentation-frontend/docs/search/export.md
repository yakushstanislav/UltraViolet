# Export

Search results can be exported as CSV directly from the API. The export
is server-rendered — no client-side post-processing required — and uses
the same query parser as the regular search response.

## API

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/search?port=443&country=NL&format=csv" \
  -o exposed-https-nl.csv
```

The handler streams the CSV with `Content-Type: text/csv`. Pagination
parameters (`limit`, `offset`) still apply; export the full result set
by combining a high `limit` (≤ 200) with multiple offset calls, or by
narrowing the query.

## Columns

The CSV columns are stable across releases:

```
ip,port,transport,protocol,country_code,asn,ptr_hostname,product,version,risk_score,last_seen,title,server_header
```

The `title` and `server_header` columns are passed through a CSV-safe
filter — any cell starting with `=`, `+`, `-`, `@`, or a tab is
prefixed with a single quote. This
disarms spreadsheet formula injection without altering the visible
content.

## UI

The Search page has an **Export CSV** button. It triggers the same API
call with the currently active filters and downloads the result.

## Scan-level delta export

A different export path covers deltas — see [Delta Exports](/delta/exports)
for `GET /v1/export/scans/{id}/delta.csv`.

## Permissions

Export is gated by the same RBAC as search itself — any authenticated
role can read it. The audit log records every export call (path,
status, requesting user) — see [Audit Log](/admin/audit).
