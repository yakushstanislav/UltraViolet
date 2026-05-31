#!/usr/bin/env bash
#
# Ad-hoc PostgreSQL backup of the running UltraViolet stack. Writes a
# pg_dump --format=custom archive to ./backups/uv-<ts>.dump.
#
# Suitable for system cron — emits no output on success when --quiet is
# passed. Retention is left to the caller (e.g. find -mtime +N -delete).

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
QUIET=0

usage() {
	cat <<'EOF'
Usage: ./backup.sh [--env-file PATH] [--quiet]

Writes backups/uv-<utc-ts>.dump using pg_dump --format=custom against the
running compose stack. Requires postgres service up and secrets/postgres_password readable.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--env-file)
		shift
		ENV_FILE=$1
		;;
	--quiet)
		QUIET=1
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
	(( QUIET )) && return 0
	printf '[backup] %s\n' "$*"
}

die() {
	printf '[backup] ERROR: %s\n' "$*" >&2
	exit 1
}

[[ -f "$ENV_FILE" ]] || die "${ENV_FILE} missing"
[[ -f secrets/postgres_password ]] || die "secrets/postgres_password missing"

mkdir -p backups

ts=$(date -u +%Y-%m-%dT%H-%M-%SZ)
outfile="backups/uv-${ts}.dump"
pw=$(cat secrets/postgres_password)

log "Creating ${outfile}"

docker compose --env-file "$ENV_FILE" -f docker-compose.yml run --rm --no-deps \
	-e PGPASSWORD="$pw" \
	-v "$(pwd)/backups:/backups:rw" \
	--entrypoint pg_dump \
	postgres \
	-h postgres -U ultraviolet -d ultraviolet \
	--format=custom --no-owner --file="/backups/uv-${ts}.dump"

log "Done: $(du -h "$outfile" | awk '{print $1}')"
