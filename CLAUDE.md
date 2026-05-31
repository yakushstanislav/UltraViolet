# UltraViolet Rules

Mandatory rules for the UltraViolet repository.

- The code-style rules below (lint, headers, imports, handler shape, DTO validation, SQL builder) apply to Go code under `service-api`.
- Frontend services (`service-frontend`, `service-documentation-frontend`) follow their own lint/format setup.
- The `Documentation (Mandatory)` rule applies to **every** service in this repository.

## Documentation (Mandatory)

Every change that adds or modifies user-visible or operator-visible functionality must update `service-documentation-frontend/docs/` in the same commit / PR. Documentation drift is treated as a blocking defect on par with a failing lint.

### Triggers

A doc update is **required** when a change touches any of the following:

| Change | Where to update |
|---|---|
| New or modified HTTP / WebSocket endpoint | `docs/api/endpoints.md` (full table) + the feature-area page that exposes it (`docs/scanning/`, `docs/hosts/`, `docs/alerts/`, …). |
| New or modified env-var | `docs/deployment/env-reference.md` (full table) + every feature page that references it. |
| New or modified SQL migration under `service-api/deploy/migrations/` | `docs/concepts/data-model.md` (migrations list + tables + indexes). |
| New protocol probe under `service-api/internal/pkg/probe/` | `docs/probes/service-protocols.md` (row with default ports + extracted fields). |
| New background worker, cron task, or retention policy | `docs/concepts/` or `docs/admin/retention.md`, plus `docs/api/metrics.md` if it adds metrics. |
| New or substantially changed UI route in `service-frontend` | The matching user-facing page under `docs/scanning/`, `docs/search/`, `docs/hosts/`, `docs/dashboard/`, `docs/alerts/`, or `docs/admin/`. |
| RBAC, JWT, rate-limit, or bootstrap behaviour change | `docs/concepts/rbac.md` and/or `docs/api/authentication.md`. |
| Change to `service-env/docker-compose.yml`, `Makefile`, `install.sh`, `upgrade.sh`, `backup.sh`, `restore.sh`, or related scripts | The corresponding page under `docs/deployment/`. |
| Change to release archive contents, dist layout, or supported install modes | `docs/deployment/offline-install.md`. |

### Hygiene

- The Reminder section at the bottom of `docs/api/endpoints.md`, `docs/deployment/env-reference.md`, and `docs/probes/service-protocols.md` is load-bearing — keep it intact.
- Internal links must resolve; VitePress fails the production build on broken links, and CI runs `npm run build`.
- Before opening the PR, run `make docs-build` (or `make -C service-documentation-frontend build`).

### Enforcement

PRs that add or modify functionality without a matching doc update are incomplete and must be sent back. The check is procedural (reviewer responsibility); CI catches syntactic mistakes via the `service-documentation-frontend build` step.

## Lint & Format

Config: `service-api/.golangci.yml`. Run: `golangci-lint run ./...`.

- Formatters: `gofmt`, `gofumpt`, `goimports` (local prefix `github.com/yakushstanislav/UltraViolet`).
- Key style linters: `wsl_v5`, `nlreturn`.

## Imports

4 groups separated by blank lines:

1. stdlib
2. third-party
3. internal DTO packages (alias as `authdto`, `featuredto`, `scandto`, …)
4. internal packages / repositories / middlewares

## Handler Style

- Declare variables at the top of the handler; separate logically distinct declarations with blank lines.
- Error handling block — keep blank lines between log, response, and `return`:

```go
if err != nil {
	requestLogger.Errorw("Can't do something", zap.Error(err))

	h.sendErrorResponse(w, http.StatusInternalServerError, ErrorInternal)

	return
}
```

## Request Validation

WantVisit-style flow:

1. Define request DTOs in `internal/dto/...` with `validate` tags.
2. Add `IsValid() error` using `gopkg.in/go-playground/validator.v9`.
3. In handlers: decode with strict `decodeBody(...)` (unknown fields disallowed), call `req.IsValid()`, return `ErrorInvalidArgument` on failure.

Don't fall back to ad-hoc `req.Field == ""` checks when DTO validation is possible.

## Input Normalization

- Frontend owns whitespace normalization.
- Do **not** `strings.TrimSpace` request payload fields in `service-api`.
- Backend validates and stores values as received.

## Naming: Repository Constructor Params

A parameter holding a repository interface must use the same full name as the struct field — no shortened aliases. Applies to constructors, `NewPipeline`, and any function that stores a repo in a struct.

```go
// Correct
func NewService(hostRepository hostrepository.Repository, dnsRepository dnsrepository.Repository) *Service

// Wrong
func NewService(hostRepo hostrepository.Repository, dnsRepo dnsrepository.Repository) *Service
```

## SQL: Squirrel Only

All SQL must be built with `github.com/Masterminds/squirrel` — no raw string concatenation, no `fmt.Sprintf` into queries.

- Each repository package keeps one package-level builder:

  ```go
  var sq = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)
  ```

- Use `sq.Select/Insert/Update/Delete(...).ToSql()`, then run on `pgkit.Querier` (`p.db.Query` / `QueryRow` / `Exec`).
- Postgres-specific bits (`GREATEST`, `||` on jsonb, `ANY($1)`, `ON CONFLICT … DO UPDATE`, CTEs) go through `squirrel.Expr(...)` and `.Suffix(...)`. No raw `pool.Exec("UPDATE …")`.
- Workers without a repository (e.g. `cvematch`, `cvesync`) build queries with the same Squirrel builder.

Raw SQL is allowed **only** in:
- migrations under `service-api/deploy/migrations/*.sql`,
- DDL inside `LISTEN/NOTIFY` setup helpers,
- parameter-less maintenance statements (e.g. `SELECT pg_advisory_lock(...)`).

If you're writing a backtick string with `SELECT`/`INSERT`/`UPDATE`/`DELETE`, stop and rewrite via `sq.*`.

## Automated Tests

Don't add or maintain tests. No `*_test.go` under `service-api`, no Vitest/Jest/Testing Library specs under `service-frontend`. "Add tests" is not part of normal implementation — add them only when explicitly requested.

## Enforcement

**Pre-commit** (`service-api/.githooks/pre-commit`): `gofmt`/`gofumpt`/`goimports`, `golangci-lint` on staged packages. Install once: `cd service-api && make setup`.

**CI** (`.github/workflows/ci.yml`, backend job): `go test ./...`, `go vet ./...`, `golangci-lint`. Any failure blocks merge.
