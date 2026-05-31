# Managing Scans

Once a scan is running, you can pause, resume, cancel, or restart it. All
mutations require `operator` or `admin`.

## List and inspect

```bash
# All scans, newest first, paginated
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans?limit=50&offset=0" | jq

# One scan with full stats and progress cursor
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans/123" | jq
```

The detail payload includes the parsed `stats` jsonb, the `progress_*`
columns, the resolved engine, and the previous scan id used as the delta
baseline.

In the UI, the Scans page lists scans with status badges, progress bars,
and inline action buttons. On narrow screens (≤880px) the list switches to
cards; scan detail shows delta events as cards and groups pause/resume/stop
actions under **More actions** when the viewport is ≤640px.

## Pause / resume

```bash
curl -s -X POST -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans/123/pause"

curl -s -X POST -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans/123/resume"
```

Pause signals the scanner to stop dispatching new targets at the next
loop iteration while letting in-flight probes complete — the scan stays
in `RUNNING` with a paused flag, no truncated data.

Resume clears the flag; the next claim loop picks the scan back up at its
progress cursor. The probe stack does not re-do already-probed
`(host, port)` pairs.

Pausing a `PENDING` scan is a no-op (nothing has started yet).

## Cancel

```bash
curl -s -X POST -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans/123/cancel"
```

Cancel signals the scanner to drain in-flight probes (≤ `PROBE_TIMEOUT`)
and then transitions to
`CANCELED`. Hosts and services that were already written stay in the
database; the delta is **not** computed for a cancelled scan.

If the scan was still `PENDING`, the API short-circuits directly to
`CANCELED` without involving the scanner.

A cancelled scan cannot be resumed. To pick up where it stopped, use
`restart` instead.

## Restart

```bash
curl -s -X POST -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/scans/123/restart"
```

Restart resets the scan parameters for a new run:

- Status resets to `PENDING`.
- The progress cursor is reset to the start of the CIDR.
- The previous snapshot is kept as the delta baseline for the next run.
- Scans interrupted by a scanner restart are reclaimed automatically —
  the watchdog uses the same path as restart.

## Realtime updates

While a scan is `RUNNING`, the WebSocket feed pushes events to every
client on `/v1/ws` with a matching JWT role. Event payloads:

| Event | Payload (excerpt) |
|---|---|
| `scan.status_changed` | `{ scan_id, status, error_msg? }` |
| `scan.progress` | `{ scan_id, done, total, target }` |
| `scan.service_observed` | `{ scan_id, host_id, ip, port, protocol }` |
| `scan.delta_ready` | `{ scan_id, summary: {new, disappeared, changed} }` |

The UI subscribes when the Scans or Scan Detail page mounts and
unsubscribes on unmount. Refer to [WebSocket](/api/websocket) for the
full schema.

## Watchdog and reclaim

If `uv-scanner` is killed mid-scan (OOM, container restart, host reboot),
the row stays in `RUNNING` but `updated_at` stops moving. The next
scanner that comes up runs `ReclaimAllRunning` on boot — it picks up any
`RUNNING` row whose `updated_at` is older than `SCANNER_RUNNING_TTL`
(default 1 h) and resumes it from the saved progress cursor.

You do not need to take manual action after a scanner crash.

## Inspecting the previous scan's baseline

The scan detail payload includes `previous_scan_id` — the row used as
the delta baseline. Open it to see what changed between the two runs.
