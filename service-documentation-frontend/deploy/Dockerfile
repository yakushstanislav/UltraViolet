
FROM node:22-alpine AS build

# VitePress lastUpdated shells out to git; without it the build fails with spawn ENOENT.
RUN apk add --no-cache git

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run build

FROM nginx:1.28-alpine

RUN apk add --no-cache curl

COPY deploy/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/docs/.vitepress/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=5s \
  CMD curl -sf http://localhost:80/ || exit 1
