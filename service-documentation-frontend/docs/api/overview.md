# API Overview

`uv-api` exposes a single versioned REST surface, a WebSocket channel,
and a Prometheus metrics endpoint. This page is the lay of the land;
the full route table is in [Endpoints](/api/endpoints).

## Base URLs

| Surface | URL | Notes |
|---|---|---|
| REST | `http://<host>:8080/v1` | When sitting behind nginx: `https://<host>/api/v1`. |
| WebSocket | `ws://<host>:8081/v1/ws` | nginx: `wss://<host>/realtime/v1/ws`. |
| Metrics | `http://<host>:9090/metrics` | Prometheus exposition format. Not protected — bind to a private interface. |
| Health | `http://<host>:8080/livez`, `/readyz`, `/v1/version` | Unauthenticated. |

The default `service-frontend` nginx proxies `/api/` to `:8080` and
`/realtime/` to `:8081`, so a browser only ever speaks to one origin.

## Versioning

`/v1` is the only published version. Breaking changes get a new prefix
(`/v2`) and the old prefix is kept until removal. The product
documentation always describes the current `/v1`.

## Authentication

All `/v1/*` routes except `/v1/auth/login`, `/v1/auth/refresh`, and
`/v1/version` require a JWT bearer token. See
[Authentication](/api/authentication) for the token model and
[RBAC](/concepts/rbac) for the role/permission mapping.

```http
Authorization: Bearer eyJhbGciOi…
```

## Health and version

```bash
curl -s http://localhost:8080/livez                 # 200 "ok"
curl -s http://localhost:8080/readyz                 # 200 + JSON
curl -s -H "authorization: bearer $TOKEN" \
  http://localhost:8080/v1/version
```

| Endpoint | Payload |
|---|---|
| `/livez` | `200 ok` if the process is up. No dependency check. |
| `/readyz` | `200` + `{status, version, commit, database}`; `503` when migrations are still running. |
| `/v1/version` | `{version, commit, built_at}`. Useful for asserting deployed build matches expectations. |

`livez` and `readyz` are public — they're used by the
container healthcheck (`HEALTHCHECK CMD curl -sf /readyz`) and any
load balancer in front of `uv-api`. They never leak schema or build
internals beyond version/commit.

## Errors

Errors are returned as a JSON object:

```json
{
  "code":    "scan_policy_violation",
  "message": "CIDR 8.8.8.0/24 is not allowed by SCAN_ALLOWED_CIDRS",
  "details": { "cidr": "8.8.8.0/24" }
}
```

| Code | Meaning |
|---|---|
| `invalid_argument` | DTO validation failed. `details` lists the bad fields. |
| `unauthenticated` | No / invalid token. |
| `forbidden` | Token role insufficient for the route. |
| `not_found` | The path-bound resource doesn't exist. |
| `conflict` | State conflict (e.g. pause-on-already-paused). |
| `scan_policy_violation` | A scan input violated `SCAN_ALLOWED_CIDRS` / `SCAN_MAX_*`. |
| `rate_limited` | Auth rate limit (HTTP `429`). |
| `feature_disabled` | Feature env is off (HTTP `503` with reason). |
| `internal` | Unhandled error. Inspect the log; the `details` is intentionally vague. |

The HTTP status code follows the obvious mapping (`400`, `401`, `403`,
`404`, `409`, `429`, `503`, `500`).

## CORS

`uv-api` reads `CORS_ALLOWED_ORIGINS` (comma-separated). For browser
clients you must include every origin the SPA serves from
(`http://localhost:5173` for `npm run dev`,
`https://uv.example.com` in production).

The WebSocket origin check is broader by default — see
[WebSocket](/api/websocket).

## Rate limiting

Only `/v1/auth/login` and `/v1/auth/refresh` are rate-limited
(`AUTH_RATE_LIMIT_RPS`, default 1; `AUTH_RATE_LIMIT_BURST`, default 5).
Other endpoints have no per-IP limit — Postgres becomes the natural
bottleneck.

If the API sits behind a CDN / NAT that collapses many clients into one
source IP, raise these envs or rely on a layer-7 WAF for the
heavy lifting.

## Content negotiation

Bodies are `application/json` in both directions. Two exceptions:

- `GET /v1/search?format=csv` and
  `GET /v1/export/scans/{id}/delta.csv` return `text/csv`.
- `POST /v1/hosts/{ip}/rtsp-snapshot` and
  `POST /v1/hosts/{ip}/onvif-rtsp-snapshot` return `image/jpeg` on
  success.

## Idempotency

The mutating endpoints are designed to be safe to retry:

- `POST /v1/scans` is **not** idempotent — every call creates a new
  scan. Use the response `id` to dedupe client-side.
- All `PATCH` endpoints are idempotent — repeated calls converge.
- `DELETE` is idempotent — calling it twice on a deleted row returns
  `404`, not an error state.

There is no `Idempotency-Key` header. The expected pattern is to look
up your client-side state and skip the call if you already have a
result.
