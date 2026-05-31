#!/usr/bin/env bash
#
# Upgrade UltraViolet with pre-migration backup and safe worker ordering.

set -euo pipefail

_uv_bootstrap_scripts_dir() {
	local source="${BASH_SOURCE[0]}"
	local dir

	while [[ -L "$source" ]]; do
		dir=$(cd -P "$(dirname "$source")" && pwd)
		source=$(readlink "$source")
		[[ "$source" != /* ]] && source="${dir}/${source}"
	done

	cd -P "$(dirname "$source")" && pwd
}

UV_SCRIPTS_DIR=$(_uv_bootstrap_scripts_dir)
# shellcheck source=lib/common.sh
source "${UV_SCRIPTS_DIR}/lib/common.sh"

ROOT_DIR=$(uv_env_root_dir)
cd "$ROOT_DIR"

ENV_FILE="${ROOT_DIR}/.env"

usage() {
	cat <<'EOF'
Usage: ./upgrade.sh [--env-file PATH]

Runs: backup → pull/load → stop scanner → migrate via uv-api → full stack up.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--env-file)
		shift
		ENV_FILE=$1
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown option: $1" >&2
		exit 1
		;;
	esac
	shift
done

log() {
	printf '[upgrade] %s\n' "$*"
}

die() {
	printf '[upgrade] ERROR: %s\n' "$*" >&2
	exit 1
}

compose() {
	docker compose --env-file "$ENV_FILE" -f docker-compose.yml "$@"
}

has_offline_images() {
	[[ -d "${ROOT_DIR}/images" ]] || return 1
	compgen -G "${ROOT_DIR}/images/"*.tar.gz >/dev/null
}

load_images() {
	[[ -d "${ROOT_DIR}/images" ]] || return 0
	shopt -s nullglob
	for archive in "${ROOT_DIR}/images/"*.tar.gz; do
		log "Loading $(basename "$archive")..."
		docker load -i "$archive"
	done
	shopt -u nullglob
}

backup_postgres() {
	mkdir -p backups
	local ts pw outfile
	ts=$(date -u +%Y%m%dT%H%M%SZ)
	pw=$(cat secrets/postgres_password)
	outfile="backups/uv-${ts}.dump"

	log "Creating pre-upgrade backup: ${outfile}"
	compose run --rm --no-deps \
		-e PGPASSWORD="$pw" \
		-v "$(pwd)/backups:/backups:rw" \
		--entrypoint pg_dump \
		postgres \
		-h postgres -U ultraviolet -d ultraviolet \
		--format=custom --no-owner --file="/backups/uv-${ts}.dump"
}

wait_readyz() {
	local deadline=$((SECONDS + 120))
	while ((SECONDS < deadline)); do
		if curl -fsS http://localhost:8080/readyz >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done

	return 1
}

main() {
	[[ -f secrets/postgres_password ]] || die "secrets/postgres_password missing"
	[[ -f "$ENV_FILE" ]] || die "${ENV_FILE} missing"

	load_images

	log "Ensuring postgres is up for backup..."
	compose up -d postgres
	compose exec -T postgres pg_isready -U ultraviolet -d ultraviolet >/dev/null ||
		die "postgres is not ready; cannot create backup"

	backup_postgres

	if has_offline_images; then
		log "Using offline images (skip pull)"
	else
		log "Pulling images..."
		compose pull
	fi

	log "Stopping uv-scanner..."
	compose stop uv-scanner || true

	log "Upgrading uv-api (migrations run on start)..."
	compose up -d uv-api

	log "Waiting for /readyz..."
	if ! wait_readyz; then
		die "uv-api not ready after upgrade"
	fi

	log "Starting remaining services..."
	compose up -d

	log "Upgrade complete."
	curl -fsS http://localhost:8080/v1/version 2>/dev/null || true
	printf '\n'
}

main "$@"
