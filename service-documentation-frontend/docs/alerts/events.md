# Alert Events

Every firing of a rule is recorded as an alert event. The Events page is
the historical view; the record is authoritative even when the
`log`/`webhook` channel is unavailable.

## Endpoint

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/alerts/events?limit=200" | jq
```

| Param | Notes |
|---|---|
| `limit` | Up to 500. |
| `before` | Event id cursor for pagination. |
| `rule_id` | Filter to a single rule. |
| `since` | ISO 8601 timestamp; events with `created_at >= since`. |

## Response

```json
{
  "events": [
    {
      "id":          7821,
      "rule_id":     14,
      "rule_name":   "RDP exposed in our space",
      "host_id":     14,
      "ip":          "198.51.100.42",
      "port":        3389,
      "protocol":    "rdp",
      "created_at":  "2026-05-17T08:35:12Z",
      "scan_id":     412,
      "delivery": {
        "channel":   "webhook",
        "status":    "delivered",
        "http_code": 200,
        "attempts":  1
      }
    },
    …
  ],
  "next_before": 7820
}
```

The `delivery` block captures the dispatch outcome:

| `status` | Meaning |
|---|---|
| `delivered` | Channel accepted the event (`log` always; `webhook` saw a 2xx response). |
| `failed` | All retries exhausted. `http_code` and `error_msg` give the reason. |
| `skipped_cooldown` | A previous event for the same `(rule, host, port)` is still inside the cooldown window. |

## UI

The Alerts page **Events** section mirrors this endpoint with URL-driven
pagination (`?ep=` and `?el=`, default 25 per page):

- Inline filters by rule, status, and date range.
- A click-through to the firing scan (`scan_id`) and the host
  (`/hosts/{ip}`).
- A "Retry delivery" action on `failed` events that posts the same
  payload to the rule's destination. Useful for transient webhook
  issues.

When a rule fires, the UI receives a realtime `alert.fired` event,
jumps the events list to page 1, and refreshes so the new row appears
at the top.

## Retention

Alert events are pruned by the retention worker every
`RETENTION_TICK_EVERY` (default 6 h) once they reach
`RETENTION_ALERT_EVENTS` (default 720 h = 30 d). Adjust the env if your
compliance window requires longer.

## Realtime

There is no dedicated WebSocket event for new alerts — subscribe to
`scan.delta_ready` and re-fetch the events for the scan, or poll the
`/v1/alerts/events?since=…` endpoint. The Alerts page listens for
`alert.fired` over the realtime WebSocket and refreshes the paginated
events list (resetting to page 1 on each new firing).

## Idempotency

The worker dedupes by `(rule_id, host_id, port)` within
`cooldown_sec`. A scan that re-observes the same exposed service won't
create a second row inside the window. Outside it, a new row is
created and the channel is dispatched.

## Roles

`GET /v1/alerts/events` — any authenticated role. Listing other
operators' rule events is intentional; events are not user-private (the
rule is the unit of ownership, not the user).

## Mobile UI

On viewports **880px and below**, the Alerts page renders both rules and
the live events feed as cards instead of wide tables. Event payloads expand
in a disclosure per card so JSON is readable without horizontal scrolling.
