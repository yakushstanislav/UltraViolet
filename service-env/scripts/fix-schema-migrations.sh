#!/usr/bin/env bash
#
# Repair golang-migrate state in schema_migrations after a failed or
# duplicate-version migration run. Detects the highest fully-applied migration
# from catalog objects and clears the dirty flag.

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
ROOT_DIR=$(cd "${UV_SCRIPTS_DIR}/.." && pwd)
cd "$ROOT_DIR"

SECRET_FILE="${ROOT_DIR}/secrets/postgres_password"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.dev.yml)

usage() {
	cat <<'EOF'
Usage: ./scripts/fix-schema-migrations.sh [--apply]

Without --apply: print current schema_migrations row and inferred version.
With --apply:    UPDATE schema_migrations (dirty=false, version=inferred).

After repair, start uv-api alone so migrations run once, then uv-scanner:
  docker compose stop uv-scanner uv-api
  docker compose up -d uv-api && docker compose up -d uv-scanner
EOF
}

apply=0
while [[ $# -gt 0 ]]; do
	case "$1" in
	--apply)
		apply=1
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown option: $1" >&2
		usage
		exit 1
		;;
	esac
	shift
done

[[ -f "$SECRET_FILE" ]] || {
	echo "missing ${SECRET_FILE}" >&2
	exit 1
}

export PGPASSWORD
PGPASSWORD=$(<"$SECRET_FILE")

psql_exec() {
	"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U ultraviolet -d ultraviolet "$@"
}

echo "Current schema_migrations:"
psql_exec -c "SELECT version, dirty FROM schema_migrations;"

inferred=$(
	psql_exec -t -A <<'SQL'
SELECT COALESCE(
  CASE
    WHEN to_regclass('public.uv_cpe_product_map') IS NOT NULL THEN 13
    WHEN to_regclass('public.uv_service_match_state') IS NOT NULL THEN 12
    WHEN EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'uv_service_cve' AND column_name = 'confidence'
    ) THEN 11
    WHEN EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'uv_cve' AND column_name = 'cvss_v31_score'
    ) THEN 10
    WHEN EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'uv_tls_certificate' AND column_name = 'sans_text'
    ) THEN 9
    ELSE 8
  END,
  8
);
SQL
)
inferred=${inferred//$'\r'/}
inferred=${inferred//$'\n'/}

echo "Inferred applied version: ${inferred}"

if [[ "$apply" -eq 0 ]]; then
	echo "Dry run. Re-run with --apply to set dirty=false and version=${inferred}."
	exit 0
fi

psql_exec -c "UPDATE schema_migrations SET version = ${inferred}, dirty = false;"
echo "Updated schema_migrations:"
psql_exec -c "SELECT version, dirty FROM schema_migrations;"
