# service-documentation-frontend

UltraViolet user and operator documentation site, built with [VitePress](https://vitepress.dev).

The site is single-language (English) and ships as a standalone nginx Docker image
(`${UV_REGISTRY}/uv-documentation:${UV_VERSION}`). It is independent of `uv-api`,
`uv-scanner`, and PostgreSQL — no runtime data, no auth, just static HTML.

## Layout

```
docs/
├── .vitepress/
│   ├── config.mts      # nav, sidebar, theme overrides
│   └── theme/          # default theme + UltraViolet CSS variables
├── public/             # static assets (favicon, illustrations)
├── index.md            # home page
└── <section>/*.md      # content
```

## Local development

```bash
npm install
npm run dev             # http://localhost:5173
```

VitePress hot-reloads on save. Broken internal links fail the production build
(see verification below).

## Production build

```bash
npm run build           # outputs to docs/.vitepress/dist
npm run preview         # serve dist/ locally on http://localhost:4173
```

## Docker

```bash
make docker             # build uv-documentation:<short-sha>
make upload             # push :short-sha and :latest to UV_REGISTRY
docker run --rm -p 8888:80 uv-documentation:<short-sha>
```

The container listens on port 80 and serves the static bundle through nginx
(see `deploy/Dockerfile` + `deploy/nginx.conf`).

## Compose

The documentation site is opt-in through the `docs` profile:

```bash
cd ../service-env
docker compose --profile docs up -d uv-documentation
# → http://localhost:3001
```

Without `--profile docs` the rest of the stack is unaffected.

## Updating content

See `CLAUDE.md` in the repository root — the `Documentation (Mandatory)`
section lists the exact triggers that require a doc update in the same
commit (new endpoint, new env var, new migration, new probe, new UI route,
RBAC/JWT/rate-limit change, install/upgrade-script change).
