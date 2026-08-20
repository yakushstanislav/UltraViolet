# Docker Registry

Production installs pull pre-built images from a registry. UltraViolet
never builds application images on the install host when you use the
registry compose files — every UltraViolet service uses
`image: ${UV_REGISTRY}/…:${UV_VERSION}`.

For air-gapped hosts use [Offline Install](/deployment/offline-install)
instead; that path loads tarred images and never calls the registry.

## Beginner path (recommended)

The simplest way to run UltraViolet from Docker Hub is
`service-env/docker-compose.registry.yml`. It pulls images, skips
PgBouncer / observability / backup sidecars, and needs only a short
`.env`.

```bash
cd service-env
cp env.registry.example .env
# REQUIRED: set POSTGRES_PASSWORD, AUTH_JWT_SECRET, AUTH_BOOTSTRAP_PASSWORD
#           (openssl rand -hex 32 for the first two)
# UV_VERSION defaults to latest (updated on each GitHub release).
# From a release tarball it is already pinned to that release.

mkdir -p geoip catalog-seed

docker compose -f docker-compose.registry.yml pull
docker compose -f docker-compose.registry.yml up -d

# UI:        http://localhost:3000
# API:       http://localhost:8080/readyz
# Docs site: docker compose -f docker-compose.registry.yml --profile docs up -d
#            → http://localhost:3002
```

| File | Purpose |
|---|---|
| `docker-compose.registry.yml` | Beginner stack — pull from registry only |
| `env.registry.example` | Minimal `.env` template for that compose file |

Stop / reset:

```bash
docker compose -f docker-compose.registry.yml down       # keep data
docker compose -f docker-compose.registry.yml down -v    # DROPS DATABASE
```

PostgreSQL stores the password from the **first** `up` in its volume.
Changing `POSTGRES_PASSWORD` in `.env` later does not update it — use
`down -v` (or keep the original password). The beginner compose uses
project name `ultraviolet-registry` so its volume does not collide with
`make dev` / full `docker-compose.yml`.

When you outgrow this file (TLS reverse proxy, PgBouncer, scheduled
backups, Prometheus), switch to the full
[Docker Compose](/deployment/docker-compose) stack and
[Installation](/getting-started/installation) (`install.sh`).

## Image names

| Service | Image |
|---|---|
| API | `${UV_REGISTRY}/uv-api:${UV_VERSION}` |
| Scanner | `${UV_REGISTRY}/uv-scanner:${UV_VERSION}` |
| Frontend | `${UV_REGISTRY}/uv-frontend:${UV_VERSION}` |
| Docs (optional) | `${UV_REGISTRY}/uv-documentation:${UV_VERSION}` |

Defaults in the beginner compose (git checkout):

```bash
UV_REGISTRY=docker.io/styakush
UV_VERSION=latest
```

Each GitHub tag release pushes `vX.Y.Z` **and** retags `:latest`.
Release archives rewrite `env.registry.example` so `UV_VERSION` matches
the packaged release (do not rely on `:latest` from a tarball).

Pin explicitly when you need a specific build:

```bash
UV_REGISTRY=docker.io/styakush
UV_VERSION=v1.0.3
```

Private registries use the same shape — only the prefix changes:

```bash
UV_REGISTRY=registry.example.com/ultraviolet
UV_VERSION=v0.1.0
```

## Authenticate to a private registry

```bash
docker login registry.example.com
# username + access token / password

# Docker Hub
docker login
# or: docker login docker.io
```

On the install host the login must succeed for the user that runs
`docker compose pull`. CI release workflows use the same credentials
via `REGISTRY_HOST`, `REGISTRY_USERNAME`, and `REGISTRY_PASSWORD`
(see the shipping `.github/workflows/release.yml`).

Full production install (archives + `install.sh`):

```bash
cp .env.example .env
# set UV_REGISTRY, UV_VERSION, secrets — see Installation
./install.sh          # docker compose pull
docker compose up -d
```

## Example Dockerfile (extend a published image)

Prefer the shipping compose stack as-is. Use a thin Dockerfile only
when you need to layer organisation-specific files (CA certs, custom
GeoIP paths baked into the image, extra tools) onto a released tag.

```dockerfile
# Dockerfile.uv-api-custom
# Build: docker build -f Dockerfile.uv-api-custom \
#   --build-arg UV_REGISTRY=docker.io/styakush \
#   --build-arg UV_VERSION=v0.1.0 \
#   -t registry.example.com/ultraviolet/uv-api:v0.1.0-custom .

ARG UV_REGISTRY=docker.io/styakush
ARG UV_VERSION=v0.1.0

FROM ${UV_REGISTRY}/uv-api:${UV_VERSION}

USER root

# Example: trust an internal CA used by outbound TLS probes / NVD mirrors.
COPY org-root-ca.crt /usr/local/share/ca-certificates/org-root-ca.crt
RUN update-ca-certificates

USER ultraviolet
```

Wire the custom tag through compose without forking the whole stack:

```yaml
# docker-compose.override.yml
services:
  uv-api:
    image: registry.example.com/ultraviolet/uv-api:v0.1.0-custom
```

The same pattern works for `uv-scanner`, `uv-frontend`, and
`uv-documentation` — change only the image name and keep the rest of
the service definition from `docker-compose.yml`.

### Frontend variant

```dockerfile
ARG UV_REGISTRY=docker.io/styakush
ARG UV_VERSION=v0.1.0

FROM ${UV_REGISTRY}/uv-frontend:${UV_VERSION}

# Runtime base-path for a sub-path deploy (must match the build-time
# VITE_BASE_PATH used when the upstream image was built, or rebuild
# the frontend from source instead of extending).
ENV UV_BASE_PATH=/ultraviolet/
```

If you need a different `VITE_BASE_PATH`, rebuild from
`service-frontend/` rather than extending a pre-built image — the SPA
assets are compiled with that path baked in.

## Shipping Dockerfiles (rebuild from source)

The images that land in the registry are built from these files in the
repository:

| Image | Dockerfile |
|---|---|
| `uv-api`, `uv-scanner` | `service-api/deploy/Dockerfile` (copies prebuilt `bin/*`) |
| `uv-frontend` | `service-frontend/deploy/Dockerfile` |
| `uv-documentation` | `service-documentation-frontend/deploy/Dockerfile` |

Release builds:

```bash
# from the repository root — builds, pushes, writes dist/ archives
make release VERSION=v0.1.0 UV_REGISTRY=docker.io/styakush
```

`uv-api` / `uv-scanner` expect linux/amd64 binaries in `service-api/bin/`
before the image build (`make -C service-api build-linux`). See
[Docker Compose](/deployment/docker-compose) for the dev overlay that
builds from source instead of pulling.

## Related

- [Installation](/getting-started/installation) — online pull vs offline load
- [Docker Compose](/deployment/docker-compose) — full production service list
- [Environment Reference](/deployment/env-reference) — `UV_REGISTRY`, `UV_VERSION`
- [Offline Install](/deployment/offline-install) — no registry access
- [Upgrade](/deployment/upgrade) — `docker compose pull` of a new tag
