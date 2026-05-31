# Secrets

UltraViolet has two persistent secrets that **must** be unique per
deployment:

1. `secrets/postgres_password` — the Postgres role password. Mounted
   into Postgres via Docker Compose secrets and read by `uv-api` /
   `uv-scanner` via the `POSTGRES_PASSWORD` env.
2. `AUTH_JWT_SECRET` — the HS256 signing key for access tokens. Lives
   in `.env` directly.

Both default to placeholder values in `.env.example`. `install.sh`
generates strong values on first run.

## File layout

```
service-env/
├── .env                       # generated from .env.example
├── secrets/
│   └── postgres_password      # one line, 32 random hex bytes
└── docker-compose.yml         # mounts secrets/postgres_password into postgres
```

`secrets/` is git-ignored. Do not commit it.

## Generation

`install.sh` runs once on first start:

```bash
[ -f secrets/postgres_password ] || openssl rand -hex 32 > secrets/postgres_password
sync_env POSTGRES_PASSWORD "$(cat secrets/postgres_password)"
```

The same call seeds `AUTH_JWT_SECRET` in `.env` if it is still set to
the placeholder. `install.sh` aborts if the placeholder is detected on
a second run — that means somebody edited `.env` to the placeholder
and forgot to set a real value.

For manual generation:

```bash
openssl rand -hex 32 > secrets/postgres_password
openssl rand -hex 32                  # paste into .env as AUTH_JWT_SECRET
```

## Rotation

### Postgres password

```bash
# 1. Pick a new password
new=$(openssl rand -hex 32)

# 2. Update Postgres
docker compose exec postgres psql -U ultraviolet -c "ALTER USER ultraviolet PASSWORD '$new';"

# 3. Update the secret file and .env
echo -n "$new" > secrets/postgres_password
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$new|" .env

# 4. Restart the API and scanner so they pick up the new env
docker compose restart uv-api uv-scanner
```

`postgres` does not need a restart — `ALTER USER` takes effect
immediately.

### JWT secret

Rotating `AUTH_JWT_SECRET` invalidates every access token in flight.
Refresh tokens stay valid (they don't depend on the JWT secret) but
clients will need to call `/v1/auth/refresh` once to pick up new
access tokens.

```bash
# 1. Pick a new secret
new=$(openssl rand -hex 32)

# 2. Update .env
sed -i "s|^AUTH_JWT_SECRET=.*|AUTH_JWT_SECRET=$new|" .env

# 3. Restart the API. Scanner does not validate tokens.
docker compose restart uv-api
```

There is no overlap window — old tokens stop working the moment
`uv-api` reads the new secret. Schedule the rotation when traffic is
low or warn API clients in advance.

## What about user passwords?

Per-user passwords live as bcrypt hashes in the database. Reset is
admin-only via `PATCH /v1/users/{id}/password` (see [Users](/admin/users))
— there is no "I forgot my password" public endpoint by design.

A user who lost their password but has no admin to reset for them is
stuck unless somebody with database access updates the password hash
directly. `uv-api hash-password` is a built-in sub-command that
prints a bcrypt hash from a plain password — use it to generate the
new hash, then update the user record in the database.

## What is **not** a secret

- `AUTH_BOOTSTRAP_USERNAME` / `AUTH_BOOTSTRAP_PASSWORD` are intentionally
  visible in `.env`. They are only honoured the first time the user
  table is empty. After bootstrap they are inert.
- `NVD_API_KEY` is technically a credential but compromise only leaks
  your NVD rate limit; treat it like any third-party API key.
- `OIDC_CLIENT_SECRET` is sensitive; store it the same way you'd store
  any OAuth client secret elsewhere.

## Backups

`secrets/postgres_password` is **not** in the database backup
(`backup.sh` runs `pg_dump`). If you restore a backup on a new host
without copying `secrets/`, Postgres will reject the API on startup
because the password file does not match the role.

Always copy `secrets/` alongside the backup, or generate a fresh
password and `ALTER USER` after restore.

## Compose secrets vs Docker Swarm secrets

The shipping stack uses Compose's `secrets:` block, which is just a
bind-mount of the local file. If you graduate to Docker Swarm or
Kubernetes, replace the file mount with the platform secret store and
keep `POSTGRES_PASSWORD_FILE` pointed at the mounted path. The
application code does not change.
