#!/usr/bin/env bash
#
# Restore a PostgreSQL backup created by ./backup.sh or upgrade.sh.
# Stops uv-api/uv-scanner, drops and recreates the public schema, then
# pg_restore into the live postgres container.

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
FORCE=0

usage() {
	cat <<'EOF'
Usage: ./restore.sh [--env-file PATH] [--force] <backups/uv-XXX.dump>

Stops uv-api and uv-scanner, drops the public schema, runs pg_restore.
WARNING: destroys existing data. Asks for confirmation unless --force is set.
EOF
}

DUMP=""

while [[ $# -gt 0 ]]; do
	case "$1" in
	--env-file)
		shift
		ENV_FILE=$1
		;;
	--force)
		FORCE=1
		;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		echo "Unknown option: $1" >&2
		exit 1
		;;
	*)
		DUMP=$1
		;;
	esac
	shift
done

log() {
	printf '[restore] %s\n' "$*"
}

die() {
	printf '[restore] ERROR: %s\n' "$*" >&2
	exit 1
}

[[ -n "$DUMP" ]] || die "missing dump path (try --help)"
[[ -f "$DUMP" ]] || die "dump file not found: $DUMP"
[[ -f "$ENV_FILE" ]] || die "${ENV_FILE} missing"
[[ -f secrets/postgres_password ]] || die "secrets/postgres_password missing"

compose() {
	docker compose --env-file "$ENV_FILE" -f docker-compose.yml "$@"
}

if (( ! FORCE )); then
	printf 'About to REPLACE the database with %s. Type "yes" to continue: ' "$DUMP"
	read -r answer
	[[ "$answer" == "yes" ]] || die "aborted"
fi

dump_basename=$(basename "$DUMP")
dump_dir=$(cd -P "$(dirname "$DUMP")" && pwd)
pw=$(cat secrets/postgres_password)

log "Stopping uv-api and uv-scanner"
compose stop uv-api uv-scanner

log "Ensuring postgres is up"
compose up -d postgres

log "Dropping and recreating public schema"
compose exec -T -e PGPASSWORD="$pw" postgres \
	psql -U ultraviolet -d ultraviolet -v ON_ERROR_STOP=1 -c \
	'DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO ultraviolet;'

log "Restoring from ${dump_basename}"
compose run --rm --no-deps \
	-e PGPASSWORD="$pw" \
	-v "${dump_dir}:/restore:ro" \
	--entrypoint pg_restore \
	postgres \
	-h postgres -U ultraviolet -d ultraviolet \
	--no-owner --no-acl --exit-on-error "/restore/${dump_basename}"

log "Bringing uv-api and uv-scanner back up"
compose up -d uv-api uv-scanner

log "Done. Tail logs with: docker compose logs -f uv-api"
