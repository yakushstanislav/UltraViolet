#!/bin/bash

set -e

SERVICE_NAME=${SERVICE_NAME:-UltraViolet}

WAIT_POSTGRES_TIMEOUT=120

check_variable()
{
    local name="$1"
    local value1=$2
    local value2=$3

    if [ -z $value1 ] && [ -z $value2 ]; then
        echo "Variable \"$name\" is not set"
        exit 1
    fi
}

check_variable "Service $SERVICE_NAME [Logger] name" $LOGGER_NAME
check_variable "Service $SERVICE_NAME [Logger] debug" $LOGGER_DEBUG

check_variable "Service $SERVICE_NAME [PostgreSQL] address" $POSTGRES_ADDR
check_variable "Service $SERVICE_NAME [PostgreSQL] port" $POSTGRES_PORT
check_variable "Service $SERVICE_NAME [PostgreSQL] name" $POSTGRES_DATABASE
check_variable "Service $SERVICE_NAME [PostgreSQL] username" $POSTGRES_USERNAME
check_variable "Service $SERVICE_NAME [PostgreSQL] max connections" $POSTGRES_MAX_CONNECTIONS

if [ -n "$POSTGRES_PASSWORD_FILE" ]; then
    if [ ! -r "$POSTGRES_PASSWORD_FILE" ]; then
        echo "Cannot read $POSTGRES_PASSWORD_FILE (uid=$(id -u)); Docker secret must be world-readable (compose secrets mode 0444)" >&2
        exit 1
    fi

    export POSTGRES_PASSWORD=$(cat "$POSTGRES_PASSWORD_FILE")
fi

if [ -n "$AUTH_JWT_SECRET_FILE" ]; then
    if [ ! -r "$AUTH_JWT_SECRET_FILE" ]; then
        echo "Cannot read $AUTH_JWT_SECRET_FILE (uid=$(id -u)); Docker secret must be world-readable (compose secrets mode 0444)" >&2
        exit 1
    fi

    export AUTH_JWT_SECRET=$(cat "$AUTH_JWT_SECRET_FILE")
fi

APP_BIN=${APP_BIN:-/ServiceAPI/uv-api}

exec /ServiceAPI/wait-for-it.sh \
    "$POSTGRES_ADDR:$POSTGRES_PORT" -t "$WAIT_POSTGRES_TIMEOUT" \
    -- "$APP_BIN"
