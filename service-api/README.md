# UltraViolet API

Go service containing `uv-api` and `uv-scanner` binaries.

## Local development

```bash
make build
```

## Docker build

```bash
make docker          # build-linux + docker buildx (local tags)
# or, for compose:
make -C ../service-env dev   # build-linux then compose --build
```

Runtime Dockerfile (`deploy/Dockerfile`) copies prebuilt binaries from
`bin/` into a minimal Alpine image — it does **not** compile Go. Always
run `make build-linux` (or `make docker` / root `make dev`) before a
compose/image build, or `COPY bin/*` will fail on an empty directory.

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
