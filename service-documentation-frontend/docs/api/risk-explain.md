# Risk Explain API

Two endpoints expose the full probability×impact breakdown the operator
needs to understand why a host or service got the score it did.

## `GET /v1/hosts/{ip}/risk-explain`

Returns the persisted host score plus the probability channels, impact
components, confidence sub-meters and the components that originally fed
the recompute (so the UI can render an "inputs" panel without a separate
round-trip).

```json
{
  "ip": "203.0.113.45",
  "risk_score": 78,
  "probability": 0.71,
  "impact": 0.62,
  "confidence": 0.84,
  "bucket": "critical",
  "updated_at": "2026-05-27T12:30:00Z",
  "factors": [
    { "code": "broad_exposure", "label": "5 high-risk services", "weight": 3 }
  ],
  "channels": [
    {
      "code": "kev",
      "label": "1 KEV-listed CVE",
      "p": 0.72,
      "sources": ["CVE-2024-12345"]
    },
    { "code": "exposure", "label": "Database service exposed", "p": 0.50 },
    { "code": "auth",     "label": "Anonymous access accepted", "p": 0.85 }
  ],
  "impacts": [
    { "code": "blast",   "label": "Blast radius",      "weight": 0.15, "contribution": 0.105 },
    { "code": "lateral", "label": "Lateral potential", "weight": 0.20, "contribution": 0.120 }
  ],
  "confidence_meters": {
    "completeness":     0.83,
    "recency":          1.00,
    "signal_quality":   0.75,
    "tag_completeness": 0.00
  },
  "components": {
    "max_service_risk":        85,
    "service_count":           8,
    "high_risk_service_count": 5,
    "kev_count":               1,
    "max_epss":                0.85,
    "critical_cve_count":      1,
    "last_seen":               "2026-05-27T10:15:00Z"
  }
}
```

`channels[].code` is one of: `kev`, `epss`, `exposure`, `auth`, `crypto`,
`app_hygiene`, `network_position`. See
[Attack-Surface Score](../concepts/attack-surface-score.md) for the
math.

`impacts[].code`: `blast`, `lateral`.

## `GET /v1/services/{id}/risk-explain`

Per-service drill-down. Re-runs `ComputeServiceProbability` against the
live signal collector and returns only the per-channel breakdown — no
impact / confidence (those are host-level). Useful for drill-down from
the host page.

```json
{
  "service_id":     98765,
  "host_id":        54321,
  "port":           3306,
  "protocol":       "mysql",
  "probability":    0.78,
  "recency_factor": 1.0,
  "channels": [
    { "code": "kev",      "p": 0.72, "sources": ["CVE-2024-12345"] },
    { "code": "exposure", "p": 0.50 },
    { "code": "auth",     "p": 0.85 }
  ]
}
```

The response is the function of current signals — it can drift from the
persisted per-service `risk_score` between the last host recompute and the
read. Use it for "live debugging", use the host endpoint for the canonical
number.

## `GET /v1/hosts/{ip}/risk-history`

Historical timeline for the host. Snapshots are appended on every
recompute that moves the score by `RISK_SNAPSHOT_MIN_DELTA` (default 2
points) or after `RISK_SNAPSHOT_MAX_IDLE` (default 24h) since the last
capture — so a stable host produces ~1 snapshot/day, a volatile one a few
per hour.

```
GET /v1/hosts/203.0.113.45/risk-history?days=30&limit=1000
```

```json
{
  "ip": "203.0.113.45",
  "points": [
    { "captured_at": "2026-04-28T00:00:00Z", "score": 42, "probability": 0.30, "impact": 0.55, "confidence": 0.72 },
    { "captured_at": "2026-05-02T08:14:00Z", "score": 78, "probability": 0.71, "impact": 0.62, "confidence": 0.84 }
  ]
}
```

Snapshots older than `RISK_EVENT_RETENTION_DAYS` (default 180) are pruned
by the retention worker.
