# Delta Exports

The delta endpoint family ships JSON and CSV variants. Use JSON for
programmatic consumers, CSV for spreadsheets and SOC tooling.

## Summary

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans/412/delta" | jq
```

```json
{
  "scan_id":             412,
  "previous_scan_id":    390,
  "new_services":        14,
  "disappeared_services": 3,
  "changed_services":    7,
  "created_at":          "2026-05-17T08:35:11Z"
}
```

## Events (paginated)

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans/412/delta/events?limit=200" | jq
```

| Param | Notes |
|---|---|
| `limit` | Up to 500. |
| `before` | Event id cursor. |
| `event_type` | Comma-separated subset of `new`, `disappeared`, `changed`. |

Response is the same `events[]` / `next_before` shape as
[Timeline](/hosts/timeline) — the same underlying table backs both
queries.

## CSV export

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/export/scans/412/delta.csv" \
  -o scan-412-delta.csv
```

The response has `Content-Type: text/csv` and
`Content-Disposition: attachment; filename="scan-delta.csv"`.

Columns:

```
event_type,host_ip,port,transport,protocol,before_banner_hash,after_banner_hash,before_product,after_product,before_version,after_version,created_at
```

Each row corresponds to one change event. The `before_*`
and `after_*` columns extract the fields the engine compared (see
[Delta Concept](/delta/concept#what-changed-considers)).

Cells are passed through `csvSafe` so values starting with `=`, `+`,
`-`, `@`, or a tab cannot trigger a spreadsheet formula execution. See
the [Export](/search/export) page for the implementation note.

## Programmatic integration patterns

- **Pipe deltas into a chat channel.** Poll `delta/events` after each
  scheduled scan completes (or subscribe to `scan.delta_ready` via WS).
  Filter to `event_type=new` and post the result to your channel.
- **Diff against an inventory.** Pipe `delta.csv` into a job that joins
  with your CMDB IDs by IP. New services without a CMDB row are
  candidates for asset review.
- **Long-term retention.** The retention worker keeps events for
  `RETENTION_CHANGE_EVENTS` (default 90 days). Push the daily CSV to
  cold storage if you need longer.

## Roles

All three delta endpoints (`/delta`, `/delta/events`,
`/export/scans/{id}/delta.csv`) accept any authenticated role. Audit
log entries are written for the CSV export too — see
[Audit Log](/admin/audit).
