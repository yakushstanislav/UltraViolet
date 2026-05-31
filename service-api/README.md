# UltraViolet API

Go service containing `uv-api` and `uv-scanner` binaries.

## Local development

```bash
make build
```

## Docker build

```bash
make docker
```

Docker image now follows the WantVisit backend pattern: binaries are built first
into `bin/` and then copied into a minimal runtime image.

## Quality gates

```bash
make fmt
make vet
make lint
```

## Git hooks

Go pre-commit runs `gofmt`, `gofumpt`, `goimports`, and `golangci-lint` for staged files.

```bash
make setup
```

## Backend style docs

- `docs/backend-style-standard.md`
- `docs/backend-style-checklist.md`
- `docs/backend-style-baseline.md`
