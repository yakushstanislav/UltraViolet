#!/bin/sh
#
# Renders /etc/nginx/conf.d/default.conf from the templated config, expanding
# UV_BASE_PATH so the same image works at "/" or at a sub-path like
# "/ultraviolet/". Must match the build-time VITE_BASE_PATH that compiled the
# SPA assets, otherwise nginx and the SPA disagree on prefixes.

set -eu

UV_BASE_PATH="${UV_BASE_PATH:-/}"

# Normalize: ensure leading and trailing slash. "" → "/", "ultraviolet" → "/ultraviolet/".
case "$UV_BASE_PATH" in
    "") UV_BASE_PATH="/" ;;
    /*) : ;;
    *)  UV_BASE_PATH="/$UV_BASE_PATH" ;;
esac

case "$UV_BASE_PATH" in
    */) : ;;
    *)  UV_BASE_PATH="$UV_BASE_PATH/" ;;
esac

export UV_BASE_PATH

envsubst '${UV_BASE_PATH}' \
    < /etc/nginx/templates/default.conf.template \
    > /etc/nginx/conf.d/default.conf
