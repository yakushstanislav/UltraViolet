# First Login

On first start, `uv-api` checks the `uv_user` table and creates a bootstrap
user if it is empty. The credentials come from `.env`:

```bash
AUTH_BOOTSTRAP_USERNAME=admin
AUTH_BOOTSTRAP_PASSWORD=admin
AUTH_BOOTSTRAP_ROLE=admin
```

## Production hardening

When `APP_ENV=production` (the default in `.env.example`), the bootstrap
flow is strict:

- `admin / admin` is **rejected** at startup — set `AUTH_BOOTSTRAP_PASSWORD`
  to a passphrase of at least 8 characters before first start.
- Passwords shorter than 8 characters are rejected outright.
- The bootstrap user is only created when the user table is empty;
  subsequent restarts never overwrite an existing user.

For development, set `APP_ENV=development` to keep `admin / admin` working.
**Do this on developer machines only.** See
[Production Checklist](/security/checklist) for the full hardening list.

## Logging in via the UI

1. Open `http://localhost:3000` (or your reverse-proxy host).
2. Enter the bootstrap username and password.
3. The UI calls `POST /v1/auth/login`, receives an access token
   (`AUTH_ACCESS_TTL`, default 15 min) and a refresh token
   (`AUTH_REFRESH_TTL`, default 168 h = 7 d), and stores them in
   browser storage.
4. You are redirected to the Dashboard.

The header shows the username, role, and a logout action. The role
controls what is visible:

| Role | Can do |
|---|---|
| `viewer` | Read dashboard, search, hosts, scans. No mutations. |
| `operator` | All viewer actions + create/manage scans, schedules, saved searches, and alerts. |
| `admin` | All operator actions + manage users and view the audit log. |

See [RBAC & Authentication](/concepts/rbac) for the underlying JWT model.

## Logging in via the API

```bash
curl -s -X POST http://localhost:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<your-password>"}' | jq

# {
#   "access_token":  "eyJhbGciOi...",
#   "refresh_token": "rt_8f3c...",
#   "access_expires_at":  "2026-05-18T10:30:00Z",
#   "refresh_expires_at": "2026-05-25T10:15:00Z"
# }
```

Subsequent calls use the bearer token:

```bash
TOKEN=eyJhbGciOi...
curl -s -H "authorization: bearer $TOKEN" http://localhost:8080/v1/me | jq
# { "role": "admin", "user_id": 1 }
```

When the access token expires, call `POST /v1/auth/refresh` with the
refresh token to get a new pair. See
[API Authentication](/api/authentication) for refresh rotation details.

## Rotating the bootstrap password

After first login, the recommended flow is:

1. Sign in as the bootstrap admin.
2. Create a personal admin account (`POST /v1/users` or the Users page).
3. Log out, sign in as the new admin.
4. Disable or delete the bootstrap user.

The bootstrap user is not special at runtime — once at least one user
exists, the bootstrap envs are inert until the database is wiped.

Next: [Quick Tour](/getting-started/quick-tour).
