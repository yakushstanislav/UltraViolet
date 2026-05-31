## Backend Style Baseline (`service-api`)

Snapshot created during style-unification rollout.

### Current baseline

- Go files scanned: 108
- DTO request structs without `IsValid()`: 0
- Main normalization hotspot in handlers before rollout:
  - `internal/http-server/handler/scan.go` (`TrimSpace` on `sort`/`order`)

### Hot zones for style drift

- `internal/http-server/handler`: handler-level error flow and request handling consistency.
- `internal/services`: query parsing conventions and validation boundaries.
- `internal/repositories`: avoid behavior-changing normalization in user-driven search filters unless explicitly required.

### Rollout notes

- Handler sort/order parsing moved away from trimming.
- Scan DTO defaults now use `ApplyDefaults()` and avoid payload normalization.
- Follow-up waves should keep style-only and behavior changes in separate PRs where possible.
