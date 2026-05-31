# Creating Scans

A scan is the unit of work in UltraViolet. It targets one CIDR range, one
port set, and one engine. This page covers the inputs, validation, and
the policy guards that apply before a scan is accepted.

## From the UI

1. **Scans → New scan**.
2. Fill in the form (see fields below).
3. Submit. The scan is inserted as `PENDING`; `uv-scanner` claims it
   within `SCANNER_WORKER_POLL_INTERVAL` (1 s by default).

## From the API

```bash
curl -s -X POST http://localhost:8080/v1/scans \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":            "Lab perimeter",
    "cidr":            "192.0.2.0/29",
    "ports":           [22, 80, 443, 3389, 8080, 8443],
    "mode":            "slow",
    "target_strategy": "sequential",
    "host_limit":      0
  }' | jq
```

Required roles: `operator` or `admin`.

## Request fields

| Field | Type | Notes |
|---|---|---|
| `name` | string, ≤ 120 chars | Free-form label shown in the UI. |
| `cidr` | string | IPv4 or IPv6 in CIDR notation. Must be inside `SCAN_ALLOWED_CIDRS`. Required for `sequential` strategy. |
| `ports` | int[] | TCP ports to scan. Up to `SCAN_MAX_PORTS` entries. |
| `mode` | enum | `slow`, `fast`, or `aggressive`. See [Modes & Strategies](/scanning/modes-and-strategies). |
| `target_strategy` | enum | `sequential` walks the CIDR; `random` samples allowed subnets; `country` samples by country. |
| `country` | string | ISO-3166-1 alpha-2 country code (e.g. `US`, `DE`). Required when `target_strategy` is `country`. |
| `host_limit` | int | When `> 0`, stop after this many hosts. Required for `random` and `country` strategies. |
| `engine` | enum, optional | `native` (default), `masscan`, `zmap`. See [Engines](/scanning/engines). |

All fields are validated before any state mutation.

### Country scan example

```bash
curl -s -X POST http://localhost:8080/v1/scans \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":            "US web sample",
    "target_strategy": "country",
    "country":         "US",
    "ports_expr":      [{"from": 80, "to": 80}, {"from": 443, "to": 443}],
    "mode":            "slow",
    "limit":           5000
  }' | jq
```

## Port presets (UI)

The form ships a small set of presets defined in
`service-frontend/src/features/Scans/portPresets.ts`:

| Preset | Ports |
|---|---|
| Web | 80, 443, 8080, 8443 |
| Mail | 25, 110, 143, 465, 587, 993, 995 |
| Databases | 1433, 1521, 3306, 5432, 6379, 27017 |
| Remote | 22, 23, 3389, 5900 |
| ICS | 102, 502, 20000, 44818, 47808 |
| Top 100 | The 100 most common TCP ports |
| Top 1k | The 1000 most common TCP ports |

Presets are convenience only — you can paste any port set into the input.

## Policy guards

Before a scan is inserted, `uv-api` enforces:

| Guard | Env | Default |
|---|---|---|
| Target CIDR is inside the allowlist | `SCAN_ALLOWED_CIDRS` | `0.0.0.0/0,::/0` (anything; tighten in production) |
| Hosts in CIDR ≤ limit | `SCAN_MAX_HOSTS` | `4096` |
| Port count ≤ limit | `SCAN_MAX_PORTS` | `65535` |
| For `random` strategy: IPv4 entries in the allowlist | (derived) | masscan/zmap are IPv4-only |
| For `country` strategy: GeoIP database loaded | `GEOIP_CITY_PATH` | Rejected at creation time if not configured |
| For `country` strategy: country code has known prefixes | (derived) | Returned as `400` if no prefixes exist for the code |
| For `country` strategy: engine must be `slow` | (derived) | `masscan`/`zmap` require an explicit CIDR |

A failing guard returns HTTP `400` with a structured error (`code:
"scan_policy_violation"`). The detail message lists which guard fired
and which value was offending.

In production, narrow `SCAN_ALLOWED_CIDRS` to the ranges you actually
own — this is the cheapest control against accidental scanning of
third-party space. See [Responsible Scanning](/security/responsible-scanning).

## What happens next

1. The row enters `PENDING`.
2. `uv-scanner` claims it within ≤ 1 s.
3. Status transitions to `RUNNING`.
4. The progress cursor updates every second
   (`SCANNER_PROGRESS_INTERVAL`).
5. WebSocket clients on `/v1/ws` see `scan.status_changed` and
   `scan.progress` events.
6. On completion, the delta is computed and `scan.delta_ready` fires.

See [Scan Lifecycle](/concepts/scan-lifecycle) for the full state
machine and [Managing Scans](/scanning/managing-scans) for pause /
resume / cancel.
