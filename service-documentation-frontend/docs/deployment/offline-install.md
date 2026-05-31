# Offline Install

The offline archives are designed for hosts without registry access —
air-gapped corporate networks, isolated lab environments, factory
appliances. They bundle Docker images, scripts, and (optionally) the
CVE seed and GeoIP MMDBs.

## Archive flavours

| Archive | Contents | Size (approx) |
|---|---|---|
| `ultraviolet-vX.Y.Z.tar.gz` | compose, scripts, `.env.example`, **no images** | ~50 KB |
| `ultraviolet-vX.Y.Z-offline.tar.gz` | + `images/*.tar.gz` (linux/amd64 Docker images) | ~500 MB |
| `ultraviolet-vX.Y.Z-offline-full.tar.gz` | + CVE seed + GeoIP MMDBs | ~1 GB |

Build them from the repository root:

```bash
git tag v0.1.0
make release VERSION=v0.1.0          # builds + pushes + writes archives to dist/
DRY_RUN=1 make release VERSION=v0.1.0 # offline-only, no push, no tag check
```

Archives land in `dist/`. They include `install.sh`, `upgrade.sh`,
`restore.sh`, `uninstall.sh`, the GeoIP downloader, the compose
files, and `.env.example`.

## Target host requirements

- **Architecture**: linux/amd64 (`uname -m` returns `x86_64`).
- **Docker Engine**: ≥ 24. The CLI must include `docker compose v2`.
- **User**: in the `docker` group, or run as root.
- **Disk**: ~10 GB free for the offline-full archive and the Postgres
  data volume.

Apple Silicon developers can build archives by setting
`DOCKER_PLATFORM=linux/amd64` (the Makefile already does this). Trying
to deploy an arm64 archive on an amd64 host fails the first `docker
load` with an architecture mismatch.

## First install

```bash
# On a machine with internet
scp dist/ultraviolet-v0.1.0-offline.tar.gz user@host:~/Downloads/

# On the target host
ssh user@host
cd ~/Downloads
tar xzf ultraviolet-v0.1.0-offline.tar.gz
cd ultraviolet-v0.1.0

# Edit .env: CORS_ALLOWED_ORIGINS, SCAN_ALLOWED_CIDRS, AUTH_BOOTSTRAP_*
cp .env.example .env
$EDITOR .env

./install.sh
```

`install.sh` flow:

1. Validates Docker reachability and the user's group membership.
2. Generates `secrets/postgres_password` if missing
   (`openssl rand -hex 32`).
3. Refuses if `.env` still contains the placeholder JWT secret.
4. **Skips registry pull** because `images/` is present.
5. Runs `docker load -i images/*.tar.gz` for each archived image
   (`uv-api`, `uv-scanner`, `uv-frontend`, optionally
   `uv-documentation`, `postgres:16-alpine`).
6. If `catalog-seed/cve-catalog.dump` exists (offline-full), drops it
   at the bind-mount location.
7. If `geoip/*.mmdb` exists (offline-full), sets `GEOIP_*_PATH` in
   `.env`.

After `install.sh`:

```bash
docker compose up -d
curl -sf http://localhost:8080/readyz
```

## Subsequent upgrades

```bash
# Source machine
tar xzf ultraviolet-v0.2.0-offline.tar.gz

# Carry over state from the existing deployment
cp ultraviolet-v0.1.0/.env       ultraviolet-v0.2.0/
cp -a ultraviolet-v0.1.0/secrets ultraviolet-v0.2.0/

cd ultraviolet-v0.2.0
./install.sh                # docker load the new images
./upgrade.sh                # backup + restart
```

Keep the previous directory around until the upgrade is verified.

## Air-gap mechanics

Nothing in UltraViolet calls home at runtime by default:

- NVD sync hits `services.nvd.nist.gov` when `CVE_SYNC_ENABLED=true`.
  Set it to `false` for air-gapped installs, or point
  `NVD_BASE_URL` at an internal mirror.
- KEV / EPSS enrichment hits CISA / Cyentia URLs. Same story —
  disable with `CVE_RISK_ENABLED=false` or point at internal mirrors.
- CT log / RDAP enrichment is off by default
  (`CTLOGS_ENABLED=false`, `RDAP_ENABLED=false`).
- The frontend nginx serves a static SPA; it does not call out.

The only outbound calls that remain useful in an air-gapped install
are protocol probes against the target network — which are the whole
point.

## Verifying images

After `install.sh`, confirm the images you loaded:

```bash
docker image ls docker.io/ultraviolet/*
docker image inspect docker.io/ultraviolet/uv-api:v0.1.0 \
  --format '{{.Architecture}}'
```

Both should say `amd64`. If you see `arm64`, you packaged the wrong
arch — rebuild with `DOCKER_PLATFORM=linux/amd64`.

## Building archives by hand

If you need a custom archive (extra files, internal branding), the
script is `service-env/scripts/build-archives.sh`. It accepts
`OFFLINE=1` and `FULL=1` flags. The default release Makefile target
calls it three times to produce all three variants.

## Uninstall

```bash
./uninstall.sh                 # docker compose down, keep volumes
./uninstall.sh --purge-data    # also drop the postgres-data volume
```

`--purge-data` is destructive — the database is gone afterwards.
Always have a recent backup before running it.
