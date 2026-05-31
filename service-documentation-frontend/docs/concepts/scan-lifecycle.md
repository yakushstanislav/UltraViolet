# Scan Lifecycle

A scan tracks its progress through a small state machine from creation
to completion.

```
        ┌─────────┐  scanner claims      ┌─────────┐
        │ PENDING │ ───────────────────▶ │ RUNNING │
        └────┬────┘                      └────┬────┘
             │                                │
             │ user calls /cancel             │ pipeline finishes
             │                                ▼
             │                          ┌─────────┐
             │                          │  DONE   │
             │                          └─────────┘
             │                                │ pipeline failed
             │                                ▼
             │                          ┌─────────┐
             │                          │ FAILED  │
             │                          └─────────┘
             │
             └─────────────────────────▶┌──────────┐
                                        │ CANCELED │
                                        └──────────┘
```

## States

| State | Meaning | Reachable from |
|---|---|---|
| `PENDING` | Inserted by `POST /v1/scans`, waiting to be claimed. | — |
| `RUNNING` | A scanner has claimed the job and is executing it. | `PENDING`, restart of a stuck run. |
| `DONE` | Pipeline completed; results are written; delta computed. | `RUNNING` |
| `FAILED` | Pipeline aborted with an error. `error_msg` is set. | `RUNNING` |
| `CANCELED` | User cancelled before completion. | `PENDING`, `RUNNING` |

## Claim

The scanner polls on every `SCANNER_WORKER_POLL_INTERVAL` (default 1 s)
for the next pending job. Only one scanner instance claims a given job at
a time. The `SCANNER_RUNNING_TTL` guard (default 1 h) lets a new scanner
reclaim work that an earlier worker started but never completed (SIGKILL,
OOM, host reboot).

On start-up, every scanner reclaims any abandoned running scans so the
deployment survives unclean shutdowns.

## Pause / resume

Two flags gate the run loop:

- **pause_requested** — set by `POST /v1/scans/{id}/pause`. The scanner
  stops dispatching new targets at the next loop tick and parks the scan
  in `RUNNING` with a paused flag. The pipeline does not transition to
  `DONE` until the scan is explicitly resumed.
- **cancel_requested** — set by `POST /v1/scans/{id}/cancel`. The scanner
  drains in-flight probes and transitions to `CANCELED`. If the scan was
  still `PENDING`, the API short-circuits to `CANCELED` directly.

`POST /v1/scans/{id}/resume` clears the pause flag; the next claim cycle
picks the scan back up at its progress cursor.

`POST /v1/scans/{id}/restart` resets the cursor to the start of the
CIDR and returns the scan to `PENDING`. Previously persisted hosts and
services are kept — the new run produces a fresh delta against the old
snapshot.

## Progress cursor

The scanner updates its progress every `SCANNER_PROGRESS_INTERVAL`
(default 1 s):

| Field | Holds |
|---|---|
| `progress_total` | Number of `(host, port)` pairs that will be probed. |
| `progress_done` | Pairs already probed. |
| `progress_target` | Last target IP touched. |
| `progress_started_at` | When the current run loop started. |

The UI converts these into the progress bar on the scan detail page;
the `/v1/ws` feed pushes them in near-real-time.

## Stats

When a scan ends, structured stats are written with:

- `hosts_scanned`, `services_found`, `cves_matched`.
- `tcp_open`, `tcp_filtered`, `udp_responsive`.
- Per-engine timing breakdowns.

These values back the dashboard tiles and the per-scan summary card.

## Delta

On `DONE`, the scanner snapshots all services touched by the scan,
compares them against the previous scan's snapshot, and writes change
events (`new`, `disappeared`, `changed`) plus an aggregate delta
summary.

See [Delta Concept](/delta/concept) for the diff algorithm and which
fields count as "changed".

## Realtime events

Every state transition is fanned out to all subscribed WebSocket clients
on `/v1/ws`. Events include `scan.created`, `scan.status_changed`,
`scan.progress`, `scan.service_observed`, `scan.delta_ready`.

The WS payload is JSON; see [WebSocket](/api/websocket) for the schema.
