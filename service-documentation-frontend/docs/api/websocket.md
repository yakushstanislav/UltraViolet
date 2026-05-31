# WebSocket

`/v1/ws` is the realtime event bus. Clients subscribe with their JWT
bearer token and receive push notifications about scan state changes,
discovered services, and delta readiness.

## Connecting

The WebSocket server listens on `REALTIME_ADDR:REALTIME_PORT`
(default `0.0.0.0:8081`). In the release stack, nginx proxies
`/realtime` to that endpoint, so a browser connects to
`wss://<host>/realtime/v1/ws`.

```js
const url = `ws://localhost:8081/v1/ws?token=${access_token}`;
const ws  = new WebSocket(url);
```

The server accepts the JWT in two places:

- `Authorization: Bearer <token>` HTTP header (preferred for non-browser
  clients).
- `?token=<jwt>` query parameter (browsers cannot set headers on the
  upgrade request, so the query form is the fallback).

The first frame after the upgrade is a `welcome` event with the
server's view of the subscription.

## Origin checks

For browser clients, `CORS_ALLOWED_ORIGINS` is also consulted on the WS
upgrade. The handler additionally accepts glob-style entries from
`127.*.*.*` on the standard Vite dev ports (3000, 4173, 5173) — this
covers port-forwarded local dev without manual config.

## Role gating

`REALTIME_WS_ALLOWED_ROLES` (default `viewer,operator,admin`) is the
allowlist of roles that can subscribe. Tightening it to
`operator,admin` is a quick way to deny viewers from seeing live scan
progress without changing the front-end.

## Event envelope

Every server-to-client message is a JSON object with a `type` and a
`payload`:

```json
{ "type": "scan.progress", "payload": { … } }
```

The currently emitted types:

| Type | Payload |
|---|---|
| `welcome` | `{ user_id, role, server_time }` |
| `scan.created` | `{ scan_id, name, cidr }` |
| `scan.status_changed` | `{ scan_id, status, error_msg? }` |
| `scan.progress` | `{ scan_id, done, total, target }` |
| `scan.service_observed` | `{ scan_id, host_id, ip, port, transport, protocol }` |
| `scan.delta_ready` | `{ scan_id, summary: { new, disappeared, changed } }` |
| `alert.fired` | `{ rule_id, host_id, ip, port }` (sent only when the alert worker dispatches with `channel=log`) |

Clients should treat unknown `type` values as ignorable — new events
may be added in minor versions.

## Source of truth: LISTEN/NOTIFY

Migration 14 added PostgreSQL `LISTEN/NOTIFY` channels for the
mutating paths. `uv-scanner` writes to a NOTIFY channel after every
state change; `uv-api` listens and fans out to connected sockets. This
keeps the WS state consistent across multiple `uv-api` instances —
all instances see every NOTIFY.

```
uv-scanner  --NOTIFY uv_scan_progress--> Postgres
                                          |
                                          v
uv-api LISTEN uv_scan_progress -----------+
   |
   +--> WebSocket clients
```

## No client → server messages

The protocol is one-way: server pushes events, clients listen. Clients
do not need to send anything after the initial upgrade. Idle
connections are pinged with WebSocket pings every 30 s; missing two
pongs in a row triggers a server-side close.

## Reconnect strategy

The SPA reconnects with exponential backoff (1 s → 30 s) on
disconnect. After reconnect, the server resends a `welcome` event but
**does not** replay missed events. If a client needs an authoritative
state after a network blip, it should fetch the relevant REST endpoint
(e.g. `GET /v1/scans/{id}`).

## Filtering

There is no server-side filtering. All subscribers receive every event
their role allows. The volume is bounded by the number of running
scans — order-of-magnitude tens of events per second per active scan,
much less when scans are quiescent.

## Errors

| Close code | Reason |
|---|---|
| `1008 policy violation` | Token missing / invalid / role not in `REALTIME_WS_ALLOWED_ROLES`. |
| `1011 server error` | Server-side panic. The next reconnect should succeed. |
| `4001` | Token expired during the connection (the server kicks the client; client should refresh and reconnect). |
