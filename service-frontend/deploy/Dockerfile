# Override base images via build args when a registry is unreachable, e.g.:
# NODE_IMAGE=public.ecr.aws/docker/library/node:22-alpine
# NGINX_IMAGE=nginxinc/nginx-unprivileged:stable-alpine
#
# Both ARGs must appear before the first FROM — Docker only substitutes ARG
# variables into FROM lines when those ARGs precede the first FROM.
ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=ghcr.io/nginxinc/nginx-unprivileged:stable-alpine
FROM ${NODE_IMAGE} AS build

WORKDIR /app

ARG VITE_API_URL=/api
ARG VITE_REALTIME_URL=/realtime
# Non-root deploy: set VITE_BASE_PATH=/ultraviolet/ at build time AND set
# UV_BASE_PATH at runtime so nginx.conf templating matches. Default "/" keeps
# the historical behavior (root deploy on a dedicated host).
ARG VITE_BASE_PATH=/
ENV VITE_API_URL=${VITE_API_URL}
ENV VITE_REALTIME_URL=${VITE_REALTIME_URL}
ENV VITE_BASE_PATH=${VITE_BASE_PATH}

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM ${NGINX_IMAGE}

USER root

RUN apk add --no-cache curl gettext

COPY deploy/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY deploy/entrypoint.sh /docker-entrypoint.d/40-render-config.sh
COPY --from=build /app/dist /usr/share/nginx/html

RUN chmod +x /docker-entrypoint.d/40-render-config.sh \
 && chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx

# Default base path; override via UV_BASE_PATH (must match VITE_BASE_PATH at
# build time).
ENV UV_BASE_PATH=/

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=5s \
  CMD curl -sf http://localhost:8080/ || exit 1
