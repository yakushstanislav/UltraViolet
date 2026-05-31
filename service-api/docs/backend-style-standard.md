## Backend Style Standard (`service-api`)

This document fixes the style baseline used for all Go changes in `service-api`.

### Mandatory rules

- Imports use 4 groups in this order:
  1. stdlib
  2. third-party
  3. internal DTO imports
  4. internal packages (repositories/services/middlewares/pkg)
- Handler error blocks follow one shape:
  - log error (if context logger is used)
  - send HTTP error response
  - `return` with a blank line before it
- Request validation flow:
  - decode using strict `decodeBody(...)`
  - run `req.IsValid()`
  - return `CodeInvalidArgument` on validation failure
- Backend does not normalize/trim request payload string fields.

### Required checks before merge

Run inside `service-api`:

```bash
gofmt -w ./...
gofumpt -w .
goimports -w -local github.com/yakushstanislav/UltraViolet .
golangci-lint run ./...
```

If using local hooks, ensure `make setup` was executed once.
