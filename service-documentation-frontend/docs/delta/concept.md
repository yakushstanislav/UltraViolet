# Delta Concept

The delta engine compares each completed scan against the most recent
prior scan of the same target. The result is a structured changelog —
three event types, one summary — that drives the Delta tab on the scan
detail page, the Timeline tab on the host page, and the
`scan.delta_ready` WebSocket event.

## Inputs

The engine compares two sets of service snapshots:

- **Current snapshot** — services observed in the just-completed scan.
- **Previous snapshot** — services from the most recent prior scan
  whose CIDR overlaps the current scan's target. The "previous" pointer
  is exposed on the API as `previous_scan_id`.

A scan with no prior run produces zero events; the engine still writes
an empty delta summary so the UI can render an empty Delta tab.

## Event types

| Type | Fired when |
|---|---|
| `new` | `(host, port, transport)` was not in the previous snapshot. |
| `disappeared` | The combination was in the previous snapshot but is absent now. |
| `changed` | The combination was in both, **and** the banner hash, fingerprint (product/version/confidence), TLS leaf cert, or HTTP status/title changed. |

Anything outside that field set is ignored — ASN drift, country flips,
and PTR changes do not produce `changed` events. This keeps the delta
signal-to-noise high: only things that actually changed on the service
appear.

## Delta summary

After each scan the engine writes a summary with counts of new,
disappeared, and changed services. The dashboard "biggest deltas" tile
and the scan detail header both display these counts.

## What "changed" considers

A `changed` event fires when any of these differ between the two
snapshots:

- Banner content (detected by comparing the banner hash)
- Detected product, version, or fingerprint confidence
- TLS leaf certificate fingerprint
- HTTP status code
- HTTP page title

Body text differences, rotating timestamps, and similar noise are
intentionally excluded to avoid flooding the view with cosmetic
changes.

## Where it runs

The delta engine is part of the scanner's end-of-scan path. It runs
before the scan transitions to `DONE`, so a scan that produces a delta
is fully consistent by the time the API marks it complete. If the engine
fails, the scan is marked `FAILED` with the partial data preserved —
it does not silently produce a stale `DONE`.

## Roles

`GET /v1/scans/{id}/delta` and
`GET /v1/scans/{id}/delta/events` — any authenticated role.
