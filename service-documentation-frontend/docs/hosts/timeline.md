# Timeline

The Timeline tab is a chronological view of every change observed on a
host. It is backed by `uv_service_change_event` rows
keyed by `(host_id, id DESC)` — the dedicated index
`uv_service_change_host_idx` keeps the page fast even when a host has
thousands of events.

## Endpoint

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/hosts/198.51.100.42/timeline?limit=100" | jq
```

| Param | Notes |
|---|---|
| `limit` | Up to 200. |
| `before` | Event id cursor for pagination — return events with `id < before`. |
| `event_type` | `new`, `disappeared`, `changed`. Comma-separated. |

## Event shape

```json
{
  "events": [
    {
      "id":          88321,
      "scan_id":     412,
      "host_id":     14,
      "event_type":  "new",
      "service":     { "port": 8443, "protocol": "https" },
      "snapshot":    { /* uv_service columns at the time */ },
      "created_at":  "2026-05-17T08:31:12Z"
    },
    {
      "id":          88010,
      "scan_id":     411,
      "host_id":     14,
      "event_type":  "changed",
      "service":     { "port": 443, "protocol": "https" },
      "before":      { "banner_hash": "abc…", "fingerprint": { "version": "1.24.0" } },
      "after":       { "banner_hash": "def…", "fingerprint": { "version": "1.25.3" } },
      "created_at":  "2026-05-10T08:30:01Z"
    },
    {
      "id":          80214,
      "scan_id":     390,
      "host_id":     14,
      "event_type":  "disappeared",
      "service":     { "port": 3389, "protocol": "rdp" },
      "before":      { /* uv_service columns from the last sighting */ },
      "created_at":  "2026-04-22T08:31:00Z"
    }
  ],
  "next_before": 80213
}
```

The three event types come from the delta engine:

| Event | Meaning |
|---|---|
| `new` | The `(host, port, transport)` was not in the previous snapshot. |
| `disappeared` | The pair was in the previous snapshot but is absent now. |
| `changed` | The pair was in both, but `banner_hash` differs **or** the fingerprint (`product`, `version`, `confidence`) changed. |

## What is in `before` / `after`

The delta engine writes only the fields it considers — banner hash,
fingerprint product/version/confidence, TLS leaf fingerprint, HTTP
title and status. Everything else (ASN, country, full HTTP body) is
omitted to keep the row small.

Migration 8 normalises the IPv4 representation in `before`/`after` to a
`/32` mask so JSON diffing on the client side is stable.

## UI

Timeline renders events as a vertical list, newest first, with:

- A type badge (green = new, red = disappeared, amber = changed).
- The port and protocol.
- For `changed` events, a diff view of the changed fields.
- A click-through to the scan that produced the event.

The page paginates server-side via the `before` cursor — there is no
total count and no offset, because the dataset can grow unbounded on
hosts with daily delta runs.

## Retention

Change events are pruned by the retention worker on a schedule.
`RETENTION_CHANGE_EVENTS` (default `2160h` = 90 days) sets the
window. Older events are deleted in batches every
`RETENTION_TICK_EVERY` (default 6 h). See [Retention](/admin/retention).

## Realtime

While a scan is running, every observed service emits a
`scan.service_observed` event on `/v1/ws`. Once the scan transitions
to `DONE`, the delta engine flushes `service_change_event` rows and
sends a single `scan.delta_ready` event. The Timeline tab does not
re-render on these events; refresh to see the new rows.
