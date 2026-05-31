# Contributing to UltraViolet

Thank you for your interest in contributing. This document explains how to get
started and what we expect in pull requests.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

## Before you start

- **Authorized scanning only.** Do not use the project to probe networks you do
  not own or lack written permission to test.
- **Issues first for large changes.** Open an issue to discuss substantial
  features or architectural changes before investing in a large PR.
- **Security issues.** Follow [SECURITY.md](SECURITY.md) — do not file public
  issues for exploitable vulnerabilities.

## Development setup

### Full stack (Docker)

```bash
cd service-env
cp .env.example .env
mkdir -p secrets
openssl rand -hex 32 > secrets/postgres_password
openssl rand -hex 32 > secrets/auth_jwt_secret

cd ..
make dev
```

UI: http://localhost:3000 · API: http://localhost:8080

### Backend hooks (recommended)

```bash
cd service-api && make setup   # installs pre-commit hooks
```

### Hybrid mode

See [README.md — Development](README.md#-development) for running PostgreSQL in
Docker and `uv-api` locally.

## Pull request checklist

Before opening a PR:

- [ ] Branch is up to date with `main`
- [ ] `make lint` passes (Go + frontend)
- [ ] `make build` succeeds for touched services
- [ ] If you changed **user-visible or operator-visible behaviour**, documentation
      is updated (see below) and `make docs-build` passes
- [ ] No secrets, `.env` files, dumps, MMDB binaries, or `node_modules` committed
- [ ] Commit messages describe **why**, not only what

## Documentation (mandatory)

Every change that affects operators or users must update
`service-documentation-frontend/docs/` in the **same PR**.

| Change | Update |
|--------|--------|
| HTTP / WebSocket endpoint | `docs/api/endpoints.md` + relevant feature page |
| Environment variable | `docs/deployment/env-reference.md` + referencing pages |
| SQL migration | `docs/concepts/data-model.md` |
| New protocol probe | `docs/probes/service-protocols.md` |
| Worker, cron, retention | `docs/concepts/` or `docs/admin/retention.md`; metrics in `docs/api/metrics.md` if applicable |
| UI route | Matching page under `docs/scanning/`, `docs/hosts/`, etc. |
| RBAC / auth / rate limits | `docs/concepts/rbac.md`, `docs/api/authentication.md` |
| Compose / install scripts | `docs/deployment/` |
| Release / offline layout | `docs/deployment/offline-install.md` |

Full rules: [`CLAUDE.md`](CLAUDE.md).

```bash
make docs-build
```

## Backend (`service-api`)

- **Go style:** `gofmt`, `gofumpt`, `goimports` (module prefix
  `github.com/yakushstanislav/UltraViolet`).
- **Lint:** `golangci-lint` — config in `service-api/.golangci.yml`.
- **SQL:** use [Squirrel](https://github.com/Masterminds/squirrel) only — no raw
  query string concatenation in application code (migrations are the exception).
- **Handlers:** DTOs with `validate` tags and `IsValid()`; strict JSON decode.
- **Tests:** we do not require new tests unless you explicitly add them or the
  issue asks for them — CI still runs `go test ./...`.

Import order (four groups, blank lines between):

1. stdlib  
2. third-party  
3. internal DTO packages (`authdto`, `scandto`, …)  
4. internal packages / repositories / middleware  

Repository constructor parameters must use the **full name** matching the struct
field (e.g. `hostRepository`, not `hostRepo`).

Do **not** `strings.TrimSpace` request payload fields in handlers — the frontend
owns normalization.

## Frontend (`service-frontend`)

```bash
cd service-frontend
npm ci
npm run lint
npm run format:check
npm run build
```

## Documentation site (`service-documentation-frontend`)

```bash
make docs-dev    # local preview
make docs-build  # production build (CI)
```

Keep internal links valid — VitePress fails the build on broken links.

## Commit and PR style

- One logical change per PR when possible.
- Use clear titles: `fix: …`, `feat: …`, `docs: …` are welcome but not required.
- Link related issues (`Fixes #123`).
- PR description: what changed, how to verify, doc updates if any.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE) that covers this project.
