#!/usr/bin/env bash
#
# Refresh GeoIP MMDB files used by uv-scanner. Designed for cron — exits 0
# even on a stale-but-existing snapshot so a transient download failure
# doesn't tear down monitoring; check the log for warnings.

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

log() {
	printf '[geoip-refresh] %s\n' "$*"
}

warn() {
	printf '[geoip-refresh] WARN: %s\n' "$*" >&2
}

DOWNLOADER="${ROOT_DIR}/geoip/download-iplocate-mmdb.sh"

[[ -x "$DOWNLOADER" ]] || {
	warn "downloader missing or not executable: ${DOWNLOADER}"
	exit 1
}

log "Starting GeoIP MMDB refresh"

if ! "$DOWNLOADER"; then
	warn "Downloader failed; keeping previous MMDB snapshots"
	exit 0
fi

log "Refreshed: $(ls -lh geoip/*.mmdb 2>/dev/null | awk '{print $9 " (" $5 ")"}')"

# Hot-reload scanner so the new MMDB is picked up (uv-scanner reads MMDB at
# startup). Restart is cheap (<5s) and only affects in-flight scans which
# auto-resume via ReclaimAllRunning.
if docker compose ps uv-scanner --status running --quiet 2>/dev/null | grep -q .; then
	log "Restarting uv-scanner to pick up the new MMDB"
	docker compose restart uv-scanner
fi

log "Done"
