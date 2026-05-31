#!/usr/bin/env bash
#
# Keep .env POSTGRES_PASSWORD in sync with secrets/postgres_password for local dev.
# postgres uses the secret file; uv-api/uv-scanner use POSTGRES_PASSWORD from .env.

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

log() {
	printf '[sync-dev-secrets] %s\n' "$*"
}

gen_secret() {
	local path=$1
	if [[ -f "$path" ]]; then
		return 0
	fi
	mkdir -p "$(dirname "$path")"
	openssl rand -hex 32 >"$path"
	chmod 600 "$path"
	log "Generated $(basename "$path")"
}

uv_set_env_from_file() {
	local key=$1
	local file=$2
	local val

	val=$(tr -d '\n\r' <"$file")
	if [[ ! -f "$ENV_FILE" ]]; then
		cp .env.example "$ENV_FILE" 2>/dev/null || touch "$ENV_FILE"
	fi
	grep -v "^${key}=" "$ENV_FILE" >"${ENV_FILE}.tmp"
	printf '%s=%s\n' "$key" "$val" >>"${ENV_FILE}.tmp"
	mv "${ENV_FILE}.tmp" "$ENV_FILE"
}

main() {
	mkdir -p secrets
	gen_secret secrets/postgres_password

	if [[ ! -f secrets/postgres_password ]]; then
		echo "Missing secrets/postgres_password" >&2
		exit 1
	fi

	uv_set_env_from_file POSTGRES_PASSWORD secrets/postgres_password
	log "POSTGRES_PASSWORD in .env matches secrets/postgres_password"
}

main "$@"
