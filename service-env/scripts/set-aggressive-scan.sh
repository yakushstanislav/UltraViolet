#!/usr/bin/env bash
#
# Apply scan tuning (default: 3x vs .env.example "fast scan" baseline) and restart uv-scanner.

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

MULTIPLIER="${1:-3}"
ENV_FILE="${ROOT_DIR}/.env"

log() {
	printf '[aggressive-scan] %s\n' "$*"
}

uv_upsert_env() {
	local key=$1
	local val=$2

	if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
		grep -v "^${key}=" "$ENV_FILE" >"${ENV_FILE}.tmp"
	else
		cp "$ENV_FILE" "${ENV_FILE}.tmp" 2>/dev/null || touch "${ENV_FILE}.tmp"
	fi

	printf '%s=%s\n' "$key" "$val" >>"${ENV_FILE}.tmp"
	mv "${ENV_FILE}.tmp" "$ENV_FILE"
}

main() {
	[[ -f "$ENV_FILE" ]] || {
		echo "Missing ${ENV_FILE}" >&2
		exit 1
	}

	case "$MULTIPLIER" in
	[1-9] | [1-9][0-9]) ;;
	*)
		echo "Multiplier must be a positive integer (got ${MULTIPLIER})" >&2
		exit 1
		;;
	esac

	log "Applying ${MULTIPLIER}x aggressive scan profile to ${ENV_FILE}"

	# Throughput / concurrency (baseline = service-env/.env.example fast-scan block).
	uv_upsert_env SCANNER_PROBE_WORKERS $((48 * MULTIPLIER))
	uv_upsert_env PORTSCAN_WORKERS $((512 * MULTIPLIER))
	uv_upsert_env PORTSCAN_RATE_PER_SEC $((5000 * MULTIPLIER))
	uv_upsert_env PORTSCAN_MAX_DIALS_PER_IP $((64 * MULTIPLIER))
	uv_upsert_env SCANNER_POSTGRES_MAX_CONNECTIONS $((48 * MULTIPLIER))
	uv_upsert_env MASSCAN_RATE $((3000 * MULTIPLIER))
	uv_upsert_env ZMAP_RATE $((1000 * MULTIPLIER))

	# Shorter waits (≈3x faster cadence / timeouts).
	uv_upsert_env PORTSCAN_TIMEOUT 1s
	uv_upsert_env PROBE_TIMEOUT 2s
	uv_upsert_env SCANNER_WORKER_POLL_INTERVAL 350ms
	uv_upsert_env SCANNER_PROGRESS_INTERVAL 350ms
	uv_upsert_env SCANNER_BACKGROUND_POLL_INTERVAL 10s
	uv_upsert_env ZMAP_COOLDOWN_SECONDS 3

	uv_upsert_env PROBE_BACKEND native

	log "Restarting uv-scanner..."
	docker compose --env-file "$ENV_FILE" -f docker-compose.yml up -d --force-recreate uv-scanner

	log "Done. Profile: PROBE_WORKERS=$((48 * MULTIPLIER)) PORTSCAN_WORKERS=$((512 * MULTIPLIER)) RATE=$((5000 * MULTIPLIER))/s"
}

main "$@"
