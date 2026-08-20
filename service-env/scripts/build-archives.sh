#!/usr/bin/env bash
#
# Build release tar.gz archives into dist/. Expects images already tagged in the local daemon.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENV_DIR="${REPO_ROOT}/service-env"
DIST_DIR="${REPO_ROOT}/dist"

UV_REGISTRY="${UV_REGISTRY:-docker.io/styakush}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
PGBOUNCER_IMAGE="${PGBOUNCER_IMAGE:-edoburu/pgbouncer:v1.25.1-p0}"
CHROMIUM_IMAGE="${CHROMIUM_IMAGE:-chromedp/headless-shell:latest}"
VERSION="${VERSION:-}"

if [[ -z "$VERSION" ]]; then
	echo "VERSION is required (e.g. VERSION=v0.1.0)" >&2
	exit 1
fi

UV_VERSION="$VERSION"
STAGING="${DIST_DIR}/.staging-${VERSION}"
ARCHIVE_BASE="ultraviolet-${VERSION}"

log() {
	printf '[build-archives] %s\n' "$*"
}

prepare_staging() {
	rm -rf "$STAGING"
	mkdir -p "$STAGING/scripts" "$STAGING/secrets.template" "$DIST_DIR"

	cp "${ENV_DIR}/docker-compose.yml" "$STAGING/"
	cp "${ENV_DIR}/.env.example" "$STAGING/"
	cp -a "${ENV_DIR}/postgres" "$STAGING/"
	echo "$VERSION" >"$STAGING/VERSION"

	cp "${ENV_DIR}/scripts/install.sh" \
		"${ENV_DIR}/scripts/upgrade.sh" \
		"${ENV_DIR}/scripts/uninstall.sh" \
		"${ENV_DIR}/scripts/set-aggressive-scan.sh" \
		"$STAGING/scripts/"
	mkdir -p "$STAGING/scripts/lib"
	cp "${ENV_DIR}/scripts/lib/common.sh" "$STAGING/scripts/lib/"

	chmod +x "$STAGING/scripts/"*.sh
	ln -sf scripts/install.sh "$STAGING/install.sh"
	ln -sf scripts/upgrade.sh "$STAGING/upgrade.sh"
	ln -sf scripts/uninstall.sh "$STAGING/uninstall.sh"

	cp "${ENV_DIR}/secrets.template/README.md" "$STAGING/secrets.template/" 2>/dev/null || true

	write_staging_readme
	prepare_staging_env_example
}

write_staging_readme() {
	# Quoted heredoc: no command substitution; placeholders replaced below.
	cat >"$STAGING/README.md" <<'UVREADME'
# UltraViolet @UV_VERSION@

Offline images (`*-offline*.tar.gz`) target linux/amd64 (x86_64 Linux).
To build on Apple Silicon, from the repository root run:
  DRY_RUN=1 make release VERSION=@UV_VERSION@

## Installation (offline, no registry)

    tar xzf @ARCHIVE_BASE@-offline.tar.gz
    cd @ARCHIVE_BASE@
    cp .env.example .env
    ./install.sh

UI: http://localhost:3000  API: http://localhost:8080

Requirements: Docker Engine 24+, docker compose, user in the `docker` group, `uname -m` = x86_64.

## Upgrade

Keep your `.env` and `secrets/`, extract the new archive, then run `./upgrade.sh`.

## Uninstall

./uninstall.sh

https://github.com/yakushstanislav/UltraViolet
UVREADME
	sed \
		-e "s/@UV_VERSION@/${VERSION}/g" \
		-e "s/@ARCHIVE_BASE@/${ARCHIVE_BASE}/g" \
		"$STAGING/README.md" >"${STAGING}/README.md.tmp"
	mv "${STAGING}/README.md.tmp" "$STAGING/README.md"
}

prepare_staging_env_example() {
	if grep -q '^UV_REGISTRY=' "$STAGING/.env.example"; then
		sed "s|^UV_REGISTRY=.*|UV_REGISTRY=${UV_REGISTRY}|" "$STAGING/.env.example" >"$STAGING/.env.example.tmp"
		mv "$STAGING/.env.example.tmp" "$STAGING/.env.example"
	fi
	if grep -q '^UV_VERSION=' "$STAGING/.env.example"; then
		sed "s/^UV_VERSION=.*/UV_VERSION=${VERSION}/" "$STAGING/.env.example" >"$STAGING/.env.example.tmp"
		mv "$STAGING/.env.example.tmp" "$STAGING/.env.example"
	fi

	# Release installs use production compose only (no local dev merge).
	grep -v '^COMPOSE_FILE=' "$STAGING/.env.example" >"$STAGING/.env.example.tmp" &&
		mv "$STAGING/.env.example.tmp" "$STAGING/.env.example"
}

pack_archive() {
	local staging_dir=$1
	local archive_file=$2
	rm -rf "${DIST_DIR}/${ARCHIVE_BASE}"
	cp -a "$staging_dir" "${DIST_DIR}/${ARCHIVE_BASE}"
	tar -czf "$archive_file" -C "$DIST_DIR" "${ARCHIVE_BASE}"
	rm -rf "${DIST_DIR}/${ARCHIVE_BASE}"
	log "Wrote $(basename "$archive_file")"
}

write_online_archive() {
	pack_archive "$STAGING" "${DIST_DIR}/${ARCHIVE_BASE}.tar.gz"
}

save_image() {
	local name=$1
	local file=$2
	log "Saving ${name} -> $(basename "$file")"
	docker save "$name" | gzip -9 >"$file"
}

require_image_arch() {
	local ref=$1
	local want_arch=$2
	local arch

	arch=$(docker image inspect "$ref" --format '{{.Architecture}}' 2>/dev/null || echo unknown)
	if [[ "$arch" != "$want_arch" ]]; then
		printf '[build-archives] ERROR: %s is %s, expected %s (DOCKER_PLATFORM=%s)\n' \
			"$ref" "$arch" "$want_arch" "$DOCKER_PLATFORM" >&2
		exit 1
	fi
}

pull_postgres_for_offline() {
	local ref=postgres:16-alpine
	log "Pulling ${ref} for ${DOCKER_PLATFORM}..."
	docker pull --platform "${DOCKER_PLATFORM}" "$ref"
	require_image_arch "$ref" amd64
}

pull_pgbouncer_for_offline() {
	log "Pulling ${PGBOUNCER_IMAGE} for ${DOCKER_PLATFORM}..."
	docker pull --platform "${DOCKER_PLATFORM}" "${PGBOUNCER_IMAGE}"
	require_image_arch "${PGBOUNCER_IMAGE}" amd64
}

pull_chromium_for_offline() {
	log "Pulling ${CHROMIUM_IMAGE} for ${DOCKER_PLATFORM}..."
	docker pull --platform "${DOCKER_PLATFORM}" "${CHROMIUM_IMAGE}"
	require_image_arch "${CHROMIUM_IMAGE}" amd64
}

write_offline_archives() {
	local offline_staging="${DIST_DIR}/.staging-offline-${VERSION}"
	rm -rf "$offline_staging"
	cp -a "$STAGING" "$offline_staging"
	mkdir -p "$offline_staging/images"

	pull_postgres_for_offline
	pull_pgbouncer_for_offline
	pull_chromium_for_offline

	local uv_images=(
		"${UV_REGISTRY}/uv-api:${UV_VERSION}"
		"${UV_REGISTRY}/uv-scanner:${UV_VERSION}"
		"${UV_REGISTRY}/uv-frontend:${UV_VERSION}"
	)
	for ref in "${uv_images[@]}"; do
		require_image_arch "$ref" amd64
	done

	save_image "${UV_REGISTRY}/uv-api:${UV_VERSION}" "$offline_staging/images/uv-api.tar.gz"
	save_image "${UV_REGISTRY}/uv-scanner:${UV_VERSION}" "$offline_staging/images/uv-scanner.tar.gz"
	save_image "${UV_REGISTRY}/uv-frontend:${UV_VERSION}" "$offline_staging/images/uv-frontend.tar.gz"
	save_image "postgres:16-alpine" "$offline_staging/images/postgres.tar.gz"
	save_image "${PGBOUNCER_IMAGE}" "$offline_staging/images/pgbouncer.tar.gz"
	save_image "${CHROMIUM_IMAGE}" "$offline_staging/images/chromium.tar.gz"

	pack_archive "$offline_staging" "${DIST_DIR}/${ARCHIVE_BASE}-offline.tar.gz"

	local full_staging="${DIST_DIR}/.staging-offline-full-${VERSION}"
	rm -rf "$full_staging"
	cp -a "$offline_staging" "$full_staging"

	local seed="${REPO_ROOT}/service-api/deploy/seed/cve-catalog.dump"
	if [[ -f "$seed" ]]; then
		mkdir -p "$full_staging/catalog-seed"
		cp "$seed" "$full_staging/catalog-seed/"
		log "Bundled cve-catalog.dump"
	fi

	if compgen -G "${ENV_DIR}/geoip/*.mmdb" >/dev/null; then
		mkdir -p "$full_staging/geoip"
		cp "${ENV_DIR}"/geoip/*.mmdb "$full_staging/geoip/"
		log "Bundled geoip/*.mmdb"
	fi

	pack_archive "$full_staging" "${DIST_DIR}/${ARCHIVE_BASE}-offline-full.tar.gz"

	rm -rf "$offline_staging" "$full_staging"
}

main() {
	prepare_staging
	write_online_archive
	write_offline_archives
	rm -rf "$STAGING"
	log "Done. Archives in ${DIST_DIR}/"
}

main "$@"
