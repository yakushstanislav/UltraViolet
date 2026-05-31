# ONVIF

ONVIF is the SOAP-based protocol used by most IP cameras for device
discovery and configuration. UltraViolet ships an ONVIF probe that
populates `uv_service_fingerprint` on discovery, plus on-demand API
endpoints that issue ONVIF commands against a known camera and return
the parsed response.

## Discovery (probe)

`internal/pkg/probe/onvif.go` fires on HTTP services that respond to a
`POST /onvif/device_service` `GetSystemInfo` SOAP envelope. The probe
extracts:

- Manufacturer, model, firmware version, serial number.
- Hardware ID.
- Media profiles (RTSP stream URIs) when the device exposes them
  anonymously.

The data lands in `uv_service_fingerprint.components` (jsonb) under the
`onvif` key. The dashboard's IoT widget surfaces hosts that look like
ONVIF cameras.

## On-demand commands

`POST /v1/hosts/{ip}/onvif-command` lets an operator issue an ONVIF
command without leaving UltraViolet — useful for validating credentials
or reading device state during an incident.

```bash
curl -s -X POST "http://localhost:8080/v1/hosts/198.51.100.42/onvif-command" \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "port":      80,
    "command":   "GetSystemDateAndTime",
    "username":  "admin",
    "password":  "12345",
    "auth":      "wsse",
    "response_shape": "json"
  }' | jq
```

| Field | Notes |
|---|---|
| `port` | TCP port — 80, 8080, 8000, … |
| `command` | One of the supported presets (see below). |
| `username` / `password` | Optional. Empty = anonymous. |
| `auth` | `basic`, `digest`, or `wsse` (WS-Security UsernameToken). Default `wsse`. |
| `response_shape` | `raw` returns the SOAP body verbatim; `json` returns parsed structured fields. Legacy `parse=true` is equivalent to `json`. |

Supported command presets (covered by `internal/pkg/probe/onvif*.go`):

- `GetSystemDateAndTime`
- `GetDeviceInformation`
- `GetSystemInfo`
- `GetCapabilities`
- `GetProfiles` (Media1)
- `GetStreamUri`

Other commands can be issued via the `raw_xml` field — the server
forwards the bytes verbatim and returns the response in
`response_shape=raw`.

## Configuration

| Env | Default | Purpose |
|---|---|---|
| `ONVIF_COMMAND_ENABLED` | `true` | Master switch. `false` makes the endpoint return `503`. |
| `ONVIF_COMMAND_TIMEOUT` | `15s` | Per-request budget. |
| `ONVIF_COMMAND_MAX_CONCURRENT` | `8` | Concurrent in-flight requests per `uv-api`. |
| `ONVIF_COMMAND_RATE_LIMIT_RPS` | `5` | Token bucket per process. `0` disables. |
| `ONVIF_COMMAND_RATE_LIMIT_BURST` | `20` | Bucket size. |
| `ONVIF_RESPONSE_CACHE_TTL` | `0s` | In-memory TTL cache for anonymous read-only calls. Disabled by default; safe values keep truncated bodies out. |

When the rate limit fires, the endpoint returns `429
onvif_rate_limited`. The limit is a per-process counter — running
multiple `uv-api` replicas scales linearly.

## ONVIF-assisted RTSP snapshot

`POST /v1/hosts/{ip}/onvif-rtsp-snapshot` queries `GetProfiles` /
`GetStreamUri` to find a live stream URI, then captures one JPEG frame
with ffmpeg. See [RTSP Snapshots](/hosts/rtsp).

## Lab credential probe (admin-only, lab-only)

`POST /v1/hosts/{ip}/onvif-lab-credential-probe` walks a small built-in
list of vendor default credentials (admin/admin, admin/12345, …) and
reports which ones — if any — authenticated. This is a noisy, intrusive
operation: it will lock out accounts on hardened devices and is
strictly admin-only.

Configuration:

| Env | Default | Purpose |
|---|---|---|
| `ONVIF_LAB_CREDENTIAL_PROBE_ENABLED` | `false` | Master switch. |
| `ONVIF_LAB_CREDENTIALS_FILE` | (empty) | Path to a credentials file (`user:pass` per line, `#` comments). Empty = use the embedded list. |
| `ONVIF_LAB_CREDENTIAL_MAX_PAIRS` | `200` | Cap on credential pairs (clamped 1–500). |
| `ONVIF_LAB_PER_ATTEMPT_TIMEOUT` | `6s` | HTTP client timeout per pair. |
| `ONVIF_LAB_INTER_ATTEMPT_DELAY` | `100ms` | Sleep between pairs. |

The endpoint returns `503 onvif_lab_probe_disabled` when the env is
`false`. The `uv_audit_event` log records every invocation (admin user,
target IP, outcome) — see [Audit Log](/admin/audit).

**Enable only in trusted lab environments.** Doing so against
production-grade cameras is destructive (logs, account lockouts,
attention from your provider).

## Failure modes

| Symptom | Meaning |
|---|---|
| `503 onvif_disabled` | `ONVIF_COMMAND_ENABLED=false`. |
| `429 onvif_rate_limited` | Exceeded the per-process token bucket. |
| `504` with `timeout` body | Device did not respond inside `ONVIF_COMMAND_TIMEOUT`. |
| `502` with `parse_error` | The device responded with malformed XML. |
| `401` with `auth_failed` | Credentials wrong, or the device requires a different `auth` mode. |
