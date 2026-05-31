#!/usr/bin/env bash

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
PURGE_DATA=0

usage() {
	cat <<'EOF'
Usage: ./uninstall.sh [--purge-data]

Stops the stack and removes volumes. With --purge-data also removes
secrets/, geoip/, and catalog-seed/ after confirmation.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--purge-data) PURGE_DATA=1 ;;
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
	printf '[uninstall] %s\n' "$*"
}

compose() {
	if [[ -f docker-compose.yml ]]; then
		docker compose --env-file "$ENV_FILE" -f docker-compose.yml "$@"
	fi
}

main() {
	if [[ -f docker-compose.yml ]]; then
		log "Stopping containers and removing volumes..."
		compose down -v
	fi

	if [[ "$PURGE_DATA" -eq 1 ]]; then
		if [[ -t 0 ]]; then
			read -rp "Remove secrets/, geoip/, catalog-seed/? [y/N] " ans
			case "$ans" in
			y | Y | yes | YES) ;;
			*)
				log "Keeping local data directories."
				exit 0
				;;
			esac
		else
			die "Refusing --purge-data without a TTY; run interactively or remove directories manually."
		fi
		rm -rf secrets geoip catalog-seed
		log "Removed secrets/, geoip/, catalog-seed/"
	fi

	log "Uninstall complete."
}

main "$@"
