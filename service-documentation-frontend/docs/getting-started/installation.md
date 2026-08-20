# Installation

UltraViolet ships as a Docker Compose stack. The release artefacts are in
`dist/` of the repository, or in your registry as
`${UV_REGISTRY}/uv-{api,scanner,frontend}:${UV_VERSION}`.

## Requirements

- **Linux x86_64**, Docker Engine ≥ 24, current user in the `docker` group.
- ~4 GB RAM minimum for a small stack; production hosts that run NVD sync
  and full CVE matching benefit from 8 GB+.
- ~10 GB free disk for PostgreSQL data (more if you keep the full CVE
  catalog with `CVE_SYNC_STORE_RAW_JSON=true`).
- macOS works for development; production targets are
  `linux/amd64`. Apple-silicon developers must build images with
  `DOCKER_PLATFORM=linux/amd64` before pushing to a production host.

## Online install (pull from registry)

```bash
tar xzf ultraviolet-v0.1.0.tar.gz && cd ultraviolet-v0.1.0
cp .env.example .env
# edit .env: UV_REGISTRY, UV_VERSION, POSTGRES_PASSWORD, AUTH_JWT_SECRET,
# AUTH_BOOTSTRAP_*, CORS, SCAN_ALLOWED_CIDRS
./install.sh             # docker compose pull + secret generation
docker compose up -d
```

`install.sh` writes `secrets/postgres_password` and
`secrets/auth_jwt_secret` if they do not exist, then runs `docker compose
pull`. It refuses to start if `.env` still contains placeholder values for
production secrets — see [Secrets](/deployment/secrets) for details.

Private registries and custom image prefixes: set `UV_REGISTRY` /
`UV_VERSION`, run `docker login`, and (optionally) extend a published
image with a thin Dockerfile — see
[Docker Registry](/deployment/docker-registry).

## Offline install (no registry access)

The `*-offline.tar.gz` archive bundles all required Docker images
(`postgres:16-alpine`, `uv-api`, `uv-scanner`, `uv-frontend`,
optionally `uv-documentation`) as a `images/` directory.

```bash
tar xzf ultraviolet-v0.1.0-offline.tar.gz && cd ultraviolet-v0.1.0
cp .env.example .env     # edit secrets, CORS, scan policy
./install.sh             # detects images/ and runs docker load, skips pull
docker compose up -d
```

The `*-offline-full.tar.gz` variant adds the CVE catalog seed
(`catalog-seed/cve-catalog.dump`) and the GeoIP MMDB files
(`geoip/ip-to-country.mmdb`, `geoip/ip-to-asn.mmdb`). See
[Offline Install](/deployment/offline-install) for the full procedure.

## Development install (source build)

**Extra requirements:** Go 1.25+ on the host (in addition to Docker). The
`uv-api` / `uv-scanner` Dockerfiles copy binaries from
`service-api/bin/` — they do not compile Go inside the image.

```bash
git clone https://github.com/<your-fork>/UltraViolet.git
cd UltraViolet
cp service-env/.env.example service-env/.env
mkdir -p service-env/secrets
openssl rand -hex 32 > service-env/secrets/postgres_password
openssl rand -hex 32 > service-env/secrets/auth_jwt_secret
make dev
```

`make dev` first runs `make -C service-api build-linux` (cross-compiles
`uv-api` and `uv-scanner` into `service-api/bin/`), then
`docker compose -f docker-compose.yml -f docker-compose.dev.yml up
--build`, which builds the API, scanner, and frontend images from
source.

After changing Go code, re-run `make -C service-api build-linux` (or
`make dev` again) so the next image build picks up new binaries.

UI is available at `http://localhost:3000`, REST API at
`http://localhost:8080`, Prometheus metrics at `http://localhost:9090`.

## What `install.sh` does

| Step | Action |
|---|---|
| 1 | Verifies Docker is reachable and the user is in the `docker` group. |
| 2 | Generates `secrets/postgres_password` and `secrets/auth_jwt_secret` if missing (`openssl rand -hex 32`). |
| 3 | Refuses to proceed if `.env` still contains placeholder JWT secret. |
| 4 | If `images/*.tar.gz` exists, runs `docker load` for each; otherwise runs `docker compose pull`. |
| 5 | If `catalog-seed/cve-catalog.dump` exists, copies it into the `uv-scanner` bind-mount path. |
| 6 | If `geoip/*.mmdb` exists, sets `GEOIP_*_PATH` in `.env`. |

After `install.sh` finishes, run `docker compose up -d` and tail the logs
with `docker compose logs -f uv-api`.

## Verification

```bash
curl -sf http://localhost:8080/readyz | jq
# {
#   "status": "ok",
#   "version": "0.1.0",
#   "commit": "abc1234"
# }
```

If `readyz` reports `database: not ready`, PostgreSQL is still applying
migrations — wait ~10 seconds and retry. See
[Troubleshooting](/troubleshooting) for diagnostics.

Next: [First Login](/getting-started/first-login).
