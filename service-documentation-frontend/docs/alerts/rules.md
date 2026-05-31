# Alert Rules

An alert rule is a saved query plus a delivery channel and a cooldown.
The background alert worker re-evaluates rules periodically against
fresh services and records events when a match fires.

## Anatomy of a rule

```bash
curl -s -X POST http://localhost:8080/v1/alerts \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":         "RDP exposed in our space",
    "query":        { "port": [3389], "country": ["NL", "DE"] },
    "channel":      "webhook",
    "destination":  "https://hooks.example.com/uv-alerts",
    "cooldown_sec": 3600,
    "enabled":      true
  }' | jq
```

| Field | Notes |
|---|---|
| `name` | Free-form label. |
| `query` | jsonb; same shape as [Search](/search/overview#url-parameters). |
| `channel` | `log` or `webhook`. |
| `destination` | URL for `webhook`; ignored for `log`. |
| `cooldown_sec` | Minimum seconds between events for the same `(host_id, port)` pair. |
| `enabled` | `true` / `false`. Disabled rules are skipped by the worker. |

Required role: `operator` or `admin`.

Referencing a saved search at create time copies its query into the
rule. Editing
the saved search later does not retroactively change the rule.

## How the worker fires

The alert worker runs on a fixed interval. On each tick:

1. Loads enabled rules.
2. For each rule, runs its query against services seen since the last
   evaluation.
3. For each match, checks the cooldown — if no event has fired for
   that `(rule, host, port)` pair inside `cooldown_sec`, records the
   event.
4. Dispatches the event:
   - `log` — writes a structured log line; the row is the durable
     record.
   - `webhook` — POSTs the event JSON to `destination`. Non-2xx
     responses are retried with backoff inside the same tick; persistent
     failures are logged but do not block other deliveries.

## Channel: `log`

```json
{
  "level":      "info",
  "msg":        "alert.fired",
  "rule_id":    14,
  "rule_name":  "RDP exposed in our space",
  "service": { "ip": "198.51.100.42", "port": 3389, "protocol": "rdp" },
  "scan_id":    412
}
```

Pipe the logs into your usual aggregator.

## Channel: `webhook`

The POST body:

```json
{
  "rule_id":       14,
  "rule_name":     "RDP exposed in our space",
  "fired_at":      "2026-05-17T08:35:12Z",
  "service": {
    "ip":          "198.51.100.42",
    "port":        3389,
    "transport":   "TCP",
    "protocol":    "rdp",
    "country":     "NL",
    "asn":         14061,
    "fingerprint": { "product": "rdp", "version": "10.0.19041" }
  },
  "scan_id":       412,
  "uv_url":        "https://uv.example.com/hosts/198.51.100.42"
}
```

`uv_url` is constructed from the request host and the configured base
path — useful for putting a clickable link in a Slack or Teams card.

## Cooldown

The cooldown is per `(rule_id, host_id, port)`. A noisy alert on the
same service won't flood the channel; a different host matching the
same rule still fires. Set `cooldown_sec=0` to disable the cooldown
(every match fires).

## Listing and toggling

```bash
# Paginated
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/alerts?limit=50&offset=0" | jq

# All rules (no pagination, useful for export)
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/alerts/all" | jq

# Enable / disable
curl -s -X PATCH "http://localhost:8080/v1/alerts/14/enabled" \
  -H "authorization: bearer $TOKEN" \
  -d '{"enabled":false}'

# Delete
curl -s -X DELETE "http://localhost:8080/v1/alerts/14" \
  -H "authorization: bearer $TOKEN"
```

`GET /v1/alerts/all` is intended for export / dashboarding; the
pagination-friendly `/v1/alerts` is what the UI uses.

## UI

The Alerts page (operator+) has two paginated sections:

- **Rules** — `?page=` and `?limit=` (default 25). Lists match counts,
  last-fire time, channel, and enabled toggle per page. Pagination sits
  at the bottom of the rules panel (in-flow, not a fixed dock).
- **Events** — `?ep=` and `?el=` (default 25). Pagination sits at the
  bottom of the events panel. New firings from the realtime feed reset
  the events section to page 1 so the latest event is visible.

Creating a rule from a saved search copies the query directly; creating
a rule from the Search page does the same.

## Tuning

If your webhook delivery target is slow, raise the cooldown rather than
making the alert worker fire less often. The worker scales naturally —
its interval is short, but cooldowns make sure individual rules don't
spam.
