#
# Shared helpers for install/upgrade/uninstall.
# Call _uv_bootstrap_scripts_dir before sourcing this file.

uv_env_root_dir() {
	cd -P "${UV_SCRIPTS_DIR}/.." && pwd
}
