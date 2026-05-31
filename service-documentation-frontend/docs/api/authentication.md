# API Authentication

UltraViolet uses JWT bearer tokens. The login endpoint exchanges a
username/password for a short-lived access token plus a long-lived
refresh token; both tokens belong to the same user.

## Login

```bash
curl -s -X POST http://localhost:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"<secret>"}' | jq

# {
#   "access_token":         "eyJhbGciOi…",
#   "refresh_token":        "rt_8f3c…",
#   "access_expires_at":    "2026-05-18T10:30:00Z",
#   "refresh_expires_at":   "2026-05-25T10:15:00Z",
#   "user": { "id": 2, "username": "alice", "role": "operator" }
# }
```

The endpoint is unauthenticated. It is rate-limited per source IP
(`AUTH_RATE_LIMIT_RPS`, `AUTH_RATE_LIMIT_BURST`); after the bucket
empties the response is `429 rate_limited`.

Failed logins return `401 unauthenticated` with no body — no
"user exists / password wrong" distinction is leaked.

## Token shape

### Access token

A JWT signed with `AUTH_JWT_SECRET` (HS256). Claims:

| Claim | Value |
|---|---|
| `sub` | User id |
| `role` | `viewer` / `operator` / `admin` |
| `username` | login name |
| `iat`, `exp` | UTC seconds |

TTL is `AUTH_ACCESS_TTL` (default 15 m). Use a short TTL — revocation
on the access path is the easiest place to take the latency hit.

### Refresh token

Opaque random bytes, base64url-encoded, prefixed `rt_`. Only the SHA-256
hash is stored. TTL is `AUTH_REFRESH_TTL` (default 168 h = 7 d).

## Refresh

```bash
curl -s -X POST http://localhost:8080/v1/auth/refresh \
  -H 'content-type: application/json' \
  -d '{"refresh_token":"rt_8f3c…"}' | jq
```

The server validates the token, rotates it, issues a fresh pair, and
returns it. Rotation is **transactional** — if
two clients race to refresh with the same token, exactly one wins; the
other gets `401 invalid_refresh_token`. Compromise of a long-lived
refresh token is bounded by its TTL because the second use invalidates
the original.

## Logout

```bash
curl -s -X POST http://localhost:8080/v1/auth/logout \
  -H "authorization: bearer $ACCESS"
```

The endpoint reads the access token (so we know which user) and deletes
**all** of that user's refresh tokens in one statement. Access tokens
remain valid until their `exp` — design for `AUTH_ACCESS_TTL` of a few
minutes if instant revocation matters.

## `GET /v1/me`

```bash
curl -s -H "authorization: bearer $ACCESS" http://localhost:8080/v1/me | jq
# { "role": "operator", "user_id": 2 }
```

A cheap sanity check. The UI calls it on every page load to detect a
stale access token; on `401` the SPA tries `POST /v1/auth/refresh`,
re-attempts the original call once, and only then redirects to login.

## Where the password lives

Passwords are stored as bcrypt hashes. The plaintext is never logged,
even at debug level, and the audit row for password mutations records
only the intent.

## Bootstrap and OIDC

- [Bootstrap](/getting-started/first-login) describes the
  `AUTH_BOOTSTRAP_*` flow.
- OIDC SSO is optional. When `OIDC_ENABLED=true`, the API also accepts
  ID tokens from the configured provider and maps them to local user
  records. The password flow keeps working alongside.

## Recommended client flow

1. Call `/v1/auth/login`. Store both tokens; show user identity from
   the returned `user` object.
2. Attach `Authorization: Bearer <access>` to every subsequent call.
3. On `401`, attempt `/v1/auth/refresh` exactly once.
4. On a second `401` (or any non-2xx from refresh), drop tokens and
   redirect to login.
5. On `/v1/auth/logout`, drop both tokens client-side regardless of
   server response.

The `service-frontend` SPA implements this flow in
`src/services/api/`. Replicate the pattern in your own clients.

## Errors

| Status | Code | Body hint |
|---|---|---|
| `401` | `unauthenticated` | No / invalid token. |
| `401` | `expired_token` | Token decoded but `exp` passed. |
| `401` | `invalid_refresh_token` | Refresh token unknown or already rotated. |
| `403` | `forbidden` | Token is valid but role lacks privilege for the route. |
| `429` | `rate_limited` | Too many login / refresh calls from this IP. |
