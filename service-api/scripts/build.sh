#!/bin/sh

set -e

check_variable()
{
    local name="$1"
    local value="$2"

    if [ -z "$value" ]; then
        echo "Variable \"$name\" is not set"
        exit 1
    fi
}

check_variable "Application name" "$APP_NAME"
check_variable "Application directory" "$APP_DIR"
check_variable "Build directory" "$BUILD_DIR"
check_variable "Build OS" "$OS"
check_variable "Build architecture" "$ARCH"

mkdir -p "$BUILD_DIR"
cd "$APP_DIR"

UV_VERSION="${UV_VERSION:-dev}"
COMMIT=$(git -C "$(dirname "$APP_DIR")/.." rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS="-X github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/buildinfo.Version=${UV_VERSION} -X github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/buildinfo.Commit=${COMMIT}"

CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/$APP_NAME"
