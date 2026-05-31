# UltraViolet secrets

Docker Compose reads passwords from files under `secrets/` (do not commit them to git).

## Files

| File | Purpose |
|------|---------|
| `postgres_password` | Password for the PostgreSQL user `ultraviolet` |
| `auth_jwt_secret` | JWT signing secret (≥ 32 bytes of entropy) |

## Creation

`install.sh` generates both files with `openssl rand -hex 32` when they do not exist yet.
Existing files are **never overwritten**.

Manual setup:

```bash
mkdir -p secrets
openssl rand -hex 32 > secrets/postgres_password
openssl rand -hex 32 > secrets/auth_jwt_secret
chmod 600 secrets/*   # on the host; in the container compose sets mode 0444 for non-root uv-api
```

Copy the template directory if needed:

```bash
cp -r secrets.template secrets
# then replace file contents with your own values
```
