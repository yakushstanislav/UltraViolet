# Schedules

A scan schedule is a cron expression plus the scan template. When the
schedule fires, `uv-api` inserts a fresh scan and the scanner picks it
up like any manual scan.

## Creating a schedule

```bash
curl -s -X POST http://localhost:8080/v1/scan-schedules \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":            "Daily perimeter",
    "cron":            "0 3 * * *",
    "cidr":            "203.0.113.0/24",
    "ports":           [22, 80, 443, 3389],
    "mode":            "fast",
    "target_strategy": "sequential",
    "enabled":         true
  }' | jq
```

Required role: `operator` or `admin`.

## Fields

| Field | Notes |
|---|---|
| `name` | Free-form label. |
| `cron` | Standard 5-field cron (`m h dom mon dow`). Evaluated in the API's `TZ`. |
| `cidr`, `ports`, `mode`, `target_strategy`, `host_limit`, `engine` | Same semantics as [Creating Scans](/scanning/creating-scans). |
| `enabled` | `true`/`false`. The scheduler ignores disabled rows. |
| `next_run_at` | Server-computed next fire time. |
| `last_run_scan_id` | The most recent scan triggered by this schedule. |

The schedule runner polls every `SCANNER_BACKGROUND_POLL_INTERVAL`
(default 30 s) and inserts a new scan whenever `next_run_at` has
passed.

## Cron syntax

Five-field cron, identical to Vixie/Linux cron:

```
┌──────── minute (0–59)
│ ┌────── hour (0–23)
│ │ ┌──── day of month (1–31)
│ │ │ ┌── month (1–12)
│ │ │ │ ┌ day of week (0–6, Sun=0)
│ │ │ │ │
* * * * *
```

Examples:

| Expression | Meaning |
|---|---|
| `0 3 * * *` | Daily at 03:00. |
| `*/15 * * * *` | Every 15 minutes. |
| `0 */6 * * *` | Every 6 hours, on the hour. |
| `0 2 * * 1-5` | 02:00 on weekdays. |
| `0 0 1 * *` | Monthly on the 1st. |

The server's timezone determines when the cron fires. Set `TZ` on the
`uv-api` container if you want local-time semantics.

## Managing schedules

```bash
# List
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scan-schedules?limit=50" | jq

# Read one
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scan-schedules/42" | jq

# Update (any subset of fields)
curl -s -X PATCH http://localhost:8080/v1/scan-schedules/42 \
  -H "authorization: bearer $TOKEN" \
  -d '{"cron":"0 4 * * *"}'

# Toggle enabled
curl -s -X PATCH http://localhost:8080/v1/scan-schedules/42/enabled \
  -H "authorization: bearer $TOKEN" \
  -d '{"enabled":false}'

# Run now (does not affect next_run_at)
curl -s -X POST http://localhost:8080/v1/scan-schedules/42/run \
  -H "authorization: bearer $TOKEN"

# Delete
curl -s -X DELETE http://localhost:8080/v1/scan-schedules/42 \
  -H "authorization: bearer $TOKEN"
```

`POST /scan-schedules/{id}/run` is useful for ad-hoc triggers — for
example, after fixing a target CIDR you can re-run the schedule
immediately without waiting for the next cron tick.

## Overlap behaviour

If a schedule fires while the previous run is still `PENDING` or
`RUNNING`, the runner refuses to insert a duplicate and logs a warning.
The next cron tick re-evaluates; you do not lose the schedule, but you
do lose the missed tick. Increase `mode=fast` (or split the CIDR into
several schedules) if your runs routinely overlap.

## UI

The Scan Schedules page lists schedules with URL-driven pagination
(`?page=` and `?limit=`, default 25). Each row shows cron, next run,
last run id, and an enabled toggle. The form uses the same field set as
the scan creation form, plus a cron input with an inline expression
preview.
