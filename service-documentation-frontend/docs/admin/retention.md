# Data Retention

The retention worker prunes data that has aged out of its window.
Without it, scan snapshots and captured HTTP bodies grow linearly with
scan count and dominate disk pressure on long-running instances.

## Configuration

```bash
RETENTION_TICK_EVERY=6h           # how often the worker runs
RETENTION_SNAPSHOTS=720h          # 30 d - keep snapshots for delta diffing
RETENTION_HTTP_BODY=720h          # 30 d - keep captured HTTP bodies
RETENTION_HTTP_SCREENSHOTS=720h   # 30 d - keep rendered HTTP thumbnails
RETENTION_CHANGE_EVENTS=2160h     # 90 d - keep delta events
RETENTION_ALERT_EVENTS=720h       # 30 d - keep alert event rows
```

Set any value to `0s` to disable pruning for that category. The audit
log has no retention knob — it is never pruned automatically.

## What each window does

### `RETENTION_SNAPSHOTS`

Prunes per-scan service snapshots. The delta engine reads the
previous-scan snapshot to compute new/disappeared/changed events.
The window controls "how far back can a fresh scan still diff against".

A 30-day window means a scan that has not run in 31+ days will compute
a delta against zero baseline — every service shows up as `new`.
Increase the window if your slow-cadence scans are losing delta context.

### `RETENTION_HTTP_BODY`

Nullifies the captured HTTP response body while keeping the rest of
the HTTP record (fingerprint, headers, status code, technologies,
redirect chain).

A 30-day window keeps body search useful while bounding the largest
data in the database. Reduce to `168h` (7 d) on disk-constrained hosts;
the search page degrades gracefully — header/title/banner search still
works, body-substring matches stop returning results for older scans.

### `RETENTION_HTTP_SCREENSHOTS`

Deletes rendered HTTP thumbnails (`uv_http_screenshot`) older than the
window. Unlike `RETENTION_HTTP_BODY` this is a full row delete because the
JPEG is the only payload — once dropped the next probe re-enqueues a render
job. Thumbnails are ~50–150 KB each; a 30-day window on a 100k-service
deployment caps the screenshot table around a few GB.

### `RETENTION_CHANGE_EVENTS`

Prunes delta change events. The Timeline tab on the host page shows
these; the dashboard's "biggest deltas" widget reads the most recent
ones.

A 90-day window balances "I can see what happened on this host last
quarter" against "the table doesn't grow forever". Increase for SOC
use cases that need quarterly diffing.

### `RETENTION_ALERT_EVENTS`

Prunes alert event rows. The Alerts page filters by date range; the
webhook delivery audit trail relies on the same rows.

A 30-day window matches a typical alerting investigation horizon.
Increase if your compliance review covers a longer period.

## What is **not** pruned

- **Host and service inventory** — the core discovered data. Pruning
  these would break references from CVE matches and change events.
- **TLS certificates** — the basis for related-host pivoting.
- **Users and refresh tokens** — identity. Expired refresh tokens are
  pruned on every token refresh.
- **Audit log** — compliance. Add your own cron if your policy requires
  rotation.
- **CVE catalog and matches** — managed separately via the CVE sync
  worker.

## Operational notes

The worker logs a one-line summary per tick:

```
retention worker tick:
  snapshots:     12340 rows pruned (window=720h)
  http_body:     8410 rows nulled  (window=720h)
  change_events: 0 rows pruned     (window=2160h)
  alert_events:  142 rows pruned   (window=720h)
```

A fresh installation prunes nothing on the first tick because nothing
is old yet. The first meaningful prune happens at
`T0 + RETENTION_TICK_EVERY` after each window opens.

If a prune tick fails, the next tick retries. The worker is idempotent
— time-range deletes are safe to repeat.

## Sizing

Rough planning numbers for a daily-scan deployment of a /24 with the
full probe stack:

| Data | Growth per scan |
|---|---|
| Service snapshots | ~250 rows (one per observed service) |
| HTTP response bodies | ~200 KiB average per HTTP service |
| Delta change events | < 50 rows typical |
| Alert events | depends on rule set, often 0–10 |

A daily scan, 30-day window, ~250 HTTP services: ~30 GB just from HTTP
bodies. Tune `RETENTION_HTTP_BODY` accordingly.
