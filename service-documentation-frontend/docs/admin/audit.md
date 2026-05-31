# Audit Log

Every authenticated mutation is recorded in the audit log. The log is
append-only — the API has no way to update or delete entries. Reading
is admin-only.

## What gets recorded

The audit middleware wraps every protected route. For each request it
writes:

| Field | Notes |
|---|---|
| User | The bearer user. Empty for failed auth attempts. |
| Method | `POST`, `PATCH`, `DELETE`, `GET` (when the route is read-sensitive). |
| Path | The route pattern (e.g. `/v1/users/{id}/role`), not the raw URI. |
| Status code | HTTP status returned. |
| Remote IP | Client IP. When `AUDIT_TRUST_PROXY_HEADERS=true`, the X-Forwarded-For chain is parsed. |
| User agent | Request user agent. |
| Error message | Server error message when status ≥ 500. |
| Timestamp | UTC. |

Read endpoints (search, dashboard, host detail) are **not** logged.
Mutations, user management, alert manipulation, RTSP/ONVIF actions are.

## Querying

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/audit?limit=200" | jq
```

| Param | Notes |
|---|---|
| `limit` | Up to 500. |
| `before` | Event id cursor. |
| `user_id` | Filter to a specific user. |
| `path` | Filter to a route pattern (URL-encode `/`). |
| `status_min`, `status_max` | HTTP status range. |
| `since`, `until` | ISO 8601 timestamps. |

## Response

```json
{
  "events": [
    {
      "id":          124581,
      "user_id":     2,
      "username":    "alice",
      "method":      "PATCH",
      "path":        "/v1/users/42/role",
      "status_code": 200,
      "remote_ip":   "203.0.113.10",
      "user_agent":  "curl/8.5.0",
      "error_msg":   null,
      "created_at":  "2026-05-17T08:31:12Z"
    },
    …
  ],
  "next_before": 124580
}
```

Deleted users still resolve correctly in the log — the username is
stored at write time, not joined at read time.

## Trust and proxies

`AUDIT_TRUST_PROXY_HEADERS=false` (default) means the IP is taken from
the TCP socket — the proxy IP if you sit behind one. Set it to `true`
when:

- A reverse proxy in front of `uv-api` adds `X-Forwarded-For` with the
  real client first.
- The proxy is trustworthy (you control it, it strips inbound XFF
  headers before adding its own).

When `true`, the middleware parses XFF right-to-left and picks the
leftmost address that is **not** in `127.0.0.0/8`, `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, or the docker bridge ranges. That
yields the originating client IP for typical proxy setups.

Setting it to `true` without a trustworthy proxy lets clients spoof
their audited IP — never enable it on a publicly exposed `uv-api`
without a real proxy.

## Retention

Audit events are not pruned by default — the assumption is that the
audit log is a compliance artefact and should be preserved.

If you must rotate, write your own scheduled job:

```sql
DELETE FROM uv_audit_event WHERE created_at < now() - INTERVAL '365 days';
```

## UI

The Audit page (admin only) renders the same data with filters for HTTP
status family (All / 2xx / 3xx / 4xx / 5xx), free-text search (path, IP,
resource), and server-side pagination. On narrow viewports (≤880px) events
appear as cards: method and HTTP status on one row, path on the next line (wraps
instead of clipping), metadata as chips, and long resource IDs on their own row
with ellipsis. The status filter is a full-width segmented control above the
search field. Pagination is fixed above the bottom nav — page summary on top,
Limit / Prev / Next in a three-column row.
