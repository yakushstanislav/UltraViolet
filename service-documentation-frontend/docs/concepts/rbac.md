# RBAC & Authentication

UltraViolet uses JWT bearer tokens with three coarse roles, enforced by
middleware on every protected route.

## Roles

| Role | Read | Mutate scans / saved searches / alerts | Admin (users, audit, lab probes) |
|---|---|---|---|
| `viewer` | yes | no | no |
| `operator` | yes | yes | no |
| `admin` | yes | yes | yes |

`Operator` inherits everything `viewer` can do; `admin` inherits both.
See [API Endpoints](/api/endpoints) for the consolidated endpoint/role
table.

## Token model

| Token | TTL env | Carrier | Purpose |
|---|---|---|---|
| Access token | `AUTH_ACCESS_TTL` (15 m) | `Authorization: Bearer <token>` | Authenticates every protected REST/WS call. |
| Refresh token | `AUTH_REFRESH_TTL` (168 h) | Request body to `POST /v1/auth/refresh` | Exchanged for a fresh pair without re-entering the password. |

The access token is a JWT signed with `AUTH_JWT_SECRET` (HS256). Claims:

| Claim | Source |
|---|---|
| `sub` | User id |
| `role` | `viewer` / `operator` / `admin` |
| `username` | Login name |
| `iat`, `exp` | UTC seconds |

The refresh token is opaque (random 32 bytes hex-encoded). Only its
hash is stored — the cleartext is shown to the client once, on login. On refresh, the row is rotated: the old token is deleted and a
new one is inserted in the same transaction.

## Endpoints

| Method | Path | Roles | Purpose |
|---|---|---|---|
| `POST` | `/v1/auth/login` | public | Exchange username/password for a token pair. |
| `POST` | `/v1/auth/refresh` | public | Rotate the token pair. |
| `POST` | `/v1/auth/logout` | viewer+ | Invalidate the refresh token. |
| `GET` | `/v1/me` | viewer+ | Returns `{role, user_id}`. |

`POST /v1/auth/login` and `POST /v1/auth/refresh` are rate-limited
per-client-IP (`AUTH_RATE_LIMIT_RPS`, `AUTH_RATE_LIMIT_BURST`). When the
service sits behind a reverse proxy, set
`AUDIT_TRUST_PROXY_HEADERS=true` so the limiter and the audit log see
the real client IP rather than the proxy IP.

## Bootstrap

When the user table is empty, `uv-api` creates a single user from
`AUTH_BOOTSTRAP_USERNAME` / `AUTH_BOOTSTRAP_PASSWORD` /
`AUTH_BOOTSTRAP_ROLE`. The check runs once at start-up.

If `APP_ENV=production`:

- `admin / admin` is rejected.
- Passwords shorter than 8 characters are rejected.
- The instance refuses to start.

See [First Login](/getting-started/first-login) for the recommended
rotation flow.

## OIDC SSO (optional)

When `OIDC_ENABLED=true`, the API accepts OIDC bearer tokens issued by
the configured provider and maps them to local user records. Required envs:

```bash
OIDC_ENABLED=true
OIDC_ISSUER_URL=https://login.example.com/realms/uv
OIDC_CLIENT_ID=ultraviolet
OIDC_CLIENT_SECRET=<from provider>
OIDC_REDIRECT_URL=https://uv.example.com/oauth/callback
OIDC_SCOPE="openid email profile"
```

OIDC is off by default; the password-based flow stays available even when
it is enabled.

## WebSocket roles

`/v1/ws` is protected by JWT exactly like REST. The set of roles that
can subscribe is the intersection of the user's role and
`REALTIME_WS_ALLOWED_ROLES` (default
`viewer,operator,admin`). Lowering this env to `operator,admin` is a
quick way to deny viewers access to live scan progress without changing
the front-end.

## Audit

Every mutating call is appended to the audit log: user, method, path,
status, remote IP, user agent, error message. The log is append-only and
only admins can read it (`GET /v1/audit`). See
[Audit Log](/admin/audit) for filters and retention.
