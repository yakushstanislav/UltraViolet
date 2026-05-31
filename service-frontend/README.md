# UltraViolet Frontend

React 19 + Vite single-page application for scan management and search UI.

## Local development

```bash
npm ci
npm run dev
```

Release images call the API via `/api` (nginx proxy). For local Vite dev:

```bash
cat > .env.local <<'EOF'
VITE_API_URL=http://localhost:8080
EOF
```

Authentication is handled via `/v1/auth/login` + `/v1/auth/refresh`.

## Quality gates

```bash
npm run lint
npm run format:check
```

## Build

```bash
npm run build
```

## Git hooks

Frontend pre-commit is based on `husky` + `lint-staged`.

```bash
npm run prepare
```
