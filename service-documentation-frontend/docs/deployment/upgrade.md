# Upgrade

`service-env/scripts/upgrade.sh` rolls a running stack forward to a new
release. It assumes you already extracted the new archive (online or
offline) into a parallel directory.

## Online upgrade

```bash
# Source machine — already extracted new tarball
cp ultraviolet-v0.1.0/.env       ultraviolet-v0.2.0/
cp -a ultraviolet-v0.1.0/secrets ultraviolet-v0.2.0/

cd ultraviolet-v0.2.0
./upgrade.sh
```

`upgrade.sh` does roughly:

1. **Backup** — runs `./scripts/backup.sh` (writes to `backups/`).
2. **Pull** — `docker compose pull` for the new images.
3. **Restart** — `docker compose up -d` (re-creates only the
   containers whose image changed).
4. **Migrate** — `uv-api` runs `golang-migrate` at startup.
5. **Health check** — polls `/readyz` until `200`.

The script aborts if any step fails. The previous deployment is still
on disk so you can roll back by `cd`ing back and running
`docker compose up -d`.

## Offline upgrade

```bash
# Source machine
tar xzf ultraviolet-v0.2.0-offline.tar.gz
cp ultraviolet-v0.1.0/.env       ultraviolet-v0.2.0/
cp -a ultraviolet-v0.1.0/secrets ultraviolet-v0.2.0/

cd ultraviolet-v0.2.0
./install.sh        # docker load from images/
./upgrade.sh        # same flow as online, but skips pull
```

`upgrade.sh` notices when the new images are already loaded (`docker
images` lookup) and skips the pull step.

## Pinned UV_VERSION

Both `install.sh` and `upgrade.sh` honour `UV_VERSION` in `.env`. To
upgrade by editing the env only:

```bash
# Edit .env
UV_VERSION=v0.2.0

# Re-pull and restart
docker compose pull
docker compose up -d
```

Useful when you maintain a fleet via configuration management and
don't want to copy a fresh archive every time.

## Directory naming

Keep the directory name stable (`ultraviolet-vX.Y.Z`). The
`postgres-data` Docker volume is named after the project, which by
default derives from the directory name. Renaming the directory
silently creates a new volume and the database appears empty.

If you must rename, either:

- `cp` the volume (`docker run --rm -v old:/from -v new:/to alpine cp -a /from/. /to/`),
  or
- pin the project name with `COMPOSE_PROJECT_NAME=ultraviolet` so
  renames do not affect the volume.

## Database migrations

`uv-api` runs migrations on every start. The runner:

- Validates the schema version stamp against the binary's known set.
- Applies missing `up.sql` files in order.
- Refuses to start on a `dirty` schema (migration interrupted) — manual
  intervention required.

If a migration takes longer than a few seconds, `/readyz` returns
`503` with `database: migrating`. The container healthcheck is set to
allow that — see [Docker Compose](/deployment/docker-compose).

## Rolling back

UltraViolet does not ship versioned `down.sql` migrations as a rollback
tool — they exist in the repo but the runner doesn't expose a downgrade
command. Roll back by:

1. Restore the pre-upgrade backup
   (`./scripts/restore.sh backups/<pre-upgrade>.dump`).
2. Pin `UV_VERSION` back to the previous version in `.env`.
3. `docker compose up -d`.

Always upgrade before reducing the binary; restoring a newer dump into
an older binary will fail (see
[Backup & Restore](/deployment/backup-restore#restoring-against-a-different-version)).

## Pre-upgrade checklist

| Item | Why |
|---|---|
| Take a fresh backup | `upgrade.sh` does this automatically, but a manual extra copy on a different host is cheap insurance. |
| Read the changelog | New required envs occasionally appear (rare but possible). |
| Confirm `.env` and `secrets/` will be carried over | Forgetting them breaks Postgres auth. |
| Verify disk space | Old images stay around until `docker image prune`. |

## Post-upgrade checklist

| Item | How |
|---|---|
| `/readyz` is `200` | `curl -sf http://localhost:8080/readyz` |
| Version matches | `curl -sH 'authorization: bearer …' http://localhost:8080/v1/version` |
| Migrations clean | `docker compose logs uv-api | grep migrate` |
| Scanner reclaimed any interrupted scans | `docker compose logs uv-scanner | grep ReclaimAllRunning` |
| Dashboard renders without errors | open the UI |
