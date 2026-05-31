# Users

User management is admin-only. The endpoints sit under `/v1/users`; the
UI page lives at Settings → Users.

## Listing

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/users?limit=50&offset=0" | jq
```

```json
{
  "users": [
    {
      "id":            1,
      "username":      "admin",
      "role":          "admin",
      "is_active":     true,
      "last_login_at": "2026-05-17T08:00:00Z",
      "created_at":    "2026-01-04T10:11:22Z"
    },
    …
  ],
  "total": 12
}
```

## Creating

```bash
curl -s -X POST http://localhost:8080/v1/users \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "username": "alice",
    "password": "<≥8 chars in production>",
    "role":     "operator"
  }' | jq
```

The password is hashed with bcrypt before insert. The plaintext is
never written anywhere — not to logs, not to the audit row.

## Reading one

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/users/42" | jq
```

## Updating

There are three single-purpose endpoints — no general `PATCH /users/{id}`:

| Endpoint | Field | Body |
|---|---|---|
| `PATCH /v1/users/{id}/role` | `role` | `{"role":"admin"}` |
| `PATCH /v1/users/{id}/password` | `password` | `{"password":"…"}` |
| `PATCH /v1/users/{id}/active` | `is_active` | `{"is_active":false}` |

Splitting these lets the audit log carry the intent explicitly. A row
that says `PATCH /users/42/role` is unambiguous; a generic `PATCH
/users/42` would require parsing the diff.

## Deleting

```bash
curl -s -X DELETE -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/users/42"
```

Deleting a user revokes all refresh tokens. Active access tokens stay
valid until expiry — design your deployment for short `AUTH_ACCESS_TTL`
if instant revocation matters.

## Reset versus disable

| Action | When |
|---|---|
| `is_active=false` | Suspend without losing history. The user cannot log in; existing refresh tokens are rejected. Re-enable with the same call. |
| Password reset | Forced rotation. Send the new password out-of-band; the user logs in with it. |
| Delete | Hard removal. Audit history is retained (the FK stays as a soft reference). |

## Demo mode

When the instance is started with `APP_DEMO_MODE=true`, the following actions
are blocked regardless of the caller's role:

| Endpoint | Returns |
|---|---|
| `POST /v1/users` | `403 {"error":"demo_mode_restricted"}` |
| `PATCH /v1/users/{id}/password` | `403 {"error":"demo_mode_restricted"}` |
| `DELETE /v1/users/{id}` | `403 {"error":"demo_mode_restricted"}` |

Read and update operations (listing, role change, active toggle) are not
affected. See [`APP_DEMO_MODE`](/deployment/env-reference#demo-mode) in the
environment reference.

## Bootstrap user

The first start of `uv-api` against an empty `uv_user` creates a user
from `AUTH_BOOTSTRAP_*`. After you create a personal admin, disable or
delete the bootstrap row. See [First Login](/getting-started/first-login).

## Audit

Every user-mutating call is recorded in the audit log — admin user,
target user id, method, status, IP. The plaintext password is never
stored; only an opaque marker. See [Audit Log](/admin/audit).

## Roles

All user-management endpoints require `admin`. Non-admin tokens get
`403`. The audit log endpoint (`GET /v1/audit`) is also admin-only.

## UI

The Users page lists all users with inline role/active controls and a
modal for create/edit. The page warns before destructive actions (role
change to `viewer` for an admin user, delete of any user, password
reset of the currently logged-in user).
