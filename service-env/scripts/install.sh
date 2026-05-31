#!/usr/bin/env bash
#
# Idempotent UltraViolet install from release archive (online or offline).

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

NON_INTERACTIVE=0
ENV_FILE="${ROOT_DIR}/.env"
SKIP_SECRETS_GEN=0

usage() {
	cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --non-interactive     Fail instead of prompting (default when stdin is not a TTY).
  --env-file PATH       Use a specific env file (default: ./.env).
  --skip-secrets-gen    Do not auto-generate missing secrets.
  -h, --help            Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--non-interactive) NON_INTERACTIVE=1 ;;
	--env-file)
		shift
		ENV_FILE=$1
		;;
	--skip-secrets-gen) SKIP_SECRETS_GEN=1 ;;
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

if [[ ! -t 0 ]]; then
	NON_INTERACTIVE=1
fi

log() {
	printf '[install] %s\n' "$*"
}

die() {
	printf '[install] ERROR: %s\n' "$*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

has_offline_images() {
	[[ -d "${ROOT_DIR}/images" ]] || return 1
	compgen -G "${ROOT_DIR}/images/"*.tar.gz >/dev/null
}

check_docker() {
	require_cmd docker
	require_cmd curl
	docker compose version >/dev/null 2>&1 || die "docker compose plugin is required"

	local ver major
	ver=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 0)
	major=${ver%%.*}
	if [[ "${major:-0}" -lt 24 ]]; then
		die "Docker Engine >= 24 required (found ${ver})"
	fi
}

load_images() {
	local images_dir="${ROOT_DIR}/images"
	[[ -d "$images_dir" ]] || return 0

	shopt -s nullglob
	local archives=("$images_dir"/*.tar.gz)
	shopt -u nullglob

	if [[ ${#archives[@]} -eq 0 ]]; then
		return 0
	fi

	log "Loading offline images from images/..."
	for archive in "${archives[@]}"; do
		log "  docker load < $(basename "$archive")"
		docker load -i "$archive"
	done

	verify_offline_images_linux_amd64
}

verify_offline_images_linux_amd64() {
	local host_arch want_arch=amd64
	host_arch=$(uname -m)
	case "$host_arch" in
	x86_64 | amd64) ;;
	*)
		log "Host CPU is ${host_arch}; release archives target linux/amd64 only."
		return 0
		;;
	esac

	local uv_registry uv_version
	uv_registry=docker.io/ultraviolet
	uv_version=dev
	if [[ -f "${ROOT_DIR}/VERSION" ]]; then
		uv_version=$(tr -d '[:space:]' <"${ROOT_DIR}/VERSION")
	fi
	if [[ -f "$ENV_FILE" ]]; then
		# shellcheck disable=SC1090
		uv_registry=$(grep -E '^UV_REGISTRY=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || echo "$uv_registry")
		uv_version=$(grep -E '^UV_VERSION=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || echo "$uv_version")
	fi

	local refs=(
		postgres:16-alpine
		edoburu/pgbouncer:v1.25.1-p0
		chromedp/headless-shell:latest
		"${uv_registry}/uv-api:${uv_version}"
		"${uv_registry}/uv-scanner:${uv_version}"
		"${uv_registry}/uv-frontend:${uv_version}"
	)

	local ref arch
	for ref in "${refs[@]}"; do
		if ! docker image inspect "$ref" >/dev/null 2>&1; then
			continue
		fi
		arch=$(docker image inspect "$ref" --format '{{.Architecture}}')
		if [[ "$arch" != "$want_arch" ]]; then
			die "Offline image ${ref} is ${arch}, but this host needs linux/${want_arch}. Rebuild the release on your workstation with: DRY_RUN=1 make release VERSION=${uv_version}"
		fi
	done
}

copy_bundled_data() {
	if [[ -d "${ROOT_DIR}/catalog-seed" ]] && [[ -n "$(ls -A "${ROOT_DIR}/catalog-seed" 2>/dev/null || true)" ]]; then
		mkdir -p "${ROOT_DIR}/catalog-seed"
		log "catalog-seed/ is ready for uv-api mount"
	fi

	if [[ -d "${ROOT_DIR}/geoip" ]] && compgen -G "${ROOT_DIR}/geoip/*.mmdb" >/dev/null; then
		mkdir -p "${ROOT_DIR}/geoip"
		log "geoip/*.mmdb present for uv-scanner mount"
	fi
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

generate_secrets() {
	[[ "$SKIP_SECRETS_GEN" -eq 0 ]] || return 0
	mkdir -p secrets
	gen_secret secrets/postgres_password
	gen_secret secrets/auth_jwt_secret
}

uv_set_env_from_file() {
	local key=$1
	local file=$2
	local val

	val=$(tr -d '\n\r' <"$file")
	grep -v "^${key}=" "$ENV_FILE" >"${ENV_FILE}.tmp"
	printf '%s=%s\n' "$key" "$val" >>"${ENV_FILE}.tmp"
	mv "${ENV_FILE}.tmp" "$ENV_FILE"
}

# uv-api/uv-scanner read POSTGRES_PASSWORD and AUTH_JWT_SECRET from .env (non-root cannot read
# compose file secrets at /run/secrets). postgres still uses secrets/postgres_password via mount.
sync_app_secrets_to_env() {
	[[ -f secrets/postgres_password ]] || return 0

	uv_set_env_from_file POSTGRES_PASSWORD secrets/postgres_password

	[[ -f secrets/auth_jwt_secret ]] || return 0

	local jwt
	jwt=$(grep -E '^AUTH_JWT_SECRET=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)
	if [[ -z "$jwt" ]] || [[ "$jwt" == "ultraviolet_local_jwt_secret_change_me" ]]; then
		uv_set_env_from_file AUTH_JWT_SECRET secrets/auth_jwt_secret
	fi
}

ensure_env() {
	if [[ ! -f "$ENV_FILE" ]]; then
		if [[ -f .env.example ]]; then
			cp .env.example "$ENV_FILE"
			log "Created $(basename "$ENV_FILE") from .env.example"
		else
			die "Missing .env and .env.example"
		fi
	fi
}

validate_env() {
	# shellcheck disable=SC1090
	set -a
	# shellcheck source=/dev/null
	source "$ENV_FILE"
	set +a

	: "${UV_REGISTRY:?UV_REGISTRY must be set in .env}"
	: "${UV_VERSION:?UV_VERSION must be set in .env}"

	local placeholders=(
		"AUTH_JWT_SECRET=ultraviolet_local_jwt_secret_change_me"
		"AUTH_BOOTSTRAP_PASSWORD=admin"
		"GRAFANA_ADMIN_PASSWORD=admin"
	)

	for entry in "${placeholders[@]}"; do
		local key=${entry%%=*}
		local bad=${entry#*=}
		local val
		val=$(grep -E "^${key}=" "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)
		if [[ -z "$val" ]] || [[ "$val" == "$bad" ]]; then
			die "Set a non-default value for ${key} in ${ENV_FILE}"
		fi
	done
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

compose() {
	docker compose --env-file "$ENV_FILE" -f docker-compose.yml "$@"
}

main() {
	check_docker
	load_images
	copy_bundled_data
	generate_secrets
	ensure_env
	sync_app_secrets_to_env
	validate_env

	if has_offline_images; then
		log "Offline images loaded; skipping pull."
	else
		log "Pulling images (online install)..."
		compose pull
	fi

	log "Starting stack..."
	compose up -d

	log "Waiting for uv-api /readyz (up to 120s)..."
	if ! wait_readyz; then
		die "uv-api did not become ready in time; check: docker compose logs uv-api"
	fi

	local version_line
	version_line=$(curl -fsS http://localhost:8080/v1/version 2>/dev/null || echo '{}')

	log "Install complete."
	printf '\n'
	printf '  Version:  %s\n' "$(echo "$version_line" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
	printf '  UI:       http://localhost:3000\n'
	printf '  API:      http://localhost:8080\n'
	printf '  Logs:     docker compose -f docker-compose.yml logs -f\n'
	printf '  Stop:     docker compose -f docker-compose.yml down\n'
	printf '\n'
}

main "$@"
