# Extending Probes

Adding a new protocol probe is a small, mechanical exercise. The pattern
is shared by every module in `service-api/internal/pkg/probe/`.

## Minimum viable probe

Create `internal/pkg/probe/<protocol>.go`:

```go

package probe

import (
	"context"
	"strings"
)

func init() {
	RegisterProbe(ProbeSpec{
		Name:      "myprotocol",
		Ports:     []int{12345},
		Transport: TransportTCP,
		Probe:     probeMyProtocol,
	})
}

func probeMyProtocol(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.DialTCP(ctx, target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	greeting, err := s.ReadBanner(ctx, conn)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(string(greeting), "MYPROTO/") {
		return nil, nil
	}

	return &Result{
		Protocol: "myprotocol",
		Banner:   greeting,
		Fingerprint: &Fingerprint{
			Product:    "MyProtocol",
			Version:    extractVersion(greeting),
			Confidence: ConfidenceHigh,
			MatchQuality: "banner_prefix",
		},
	}, nil
}
```

What each piece does:

| Element | Role |
|---|---|
| `RegisterProbe` in `init()` | Adds the probe to the dispatcher's port map and protocol list. |
| `ProbeSpec.Name` | Short identifier; used in logs, metrics, and `uv_service.protocol`. |
| `ProbeSpec.Ports` | Ports the dispatcher routes to this probe. Use `[]int{0}` for "match any open port if other probes failed". |
| `ProbeSpec.Transport` | `TransportTCP` or `TransportUDP`. |
| `probeMyProtocol` | The work. Returns `(*Result, error)`. |

Return `(nil, nil)` to disclaim — the dispatcher falls through to the
generic banner/fallback path. Return `(nil, err)` to log the failure but
not poison the service row.

## Stack helpers

`*Stack` is the per-scan context — it owns the TCP/TLS dialer,
resolver, rate limiter, and HTTP client. Use the helpers instead of
talking to the stdlib directly:

| Helper | Use |
|---|---|
| `s.DialTCP(ctx, target)` | TCP connect with `PORTSCAN_TIMEOUT`. |
| `s.DialTLS(ctx, target)` | TLS dial; auto-captures the cert chain. |
| `s.HTTPClient()` | Shared HTTP client; reuses connections within a host. |
| `s.ReadBanner(ctx, conn)` | Reads up to `PROBE_MAX_BODY_BYTES` with `PROBE_TIMEOUT`. |

The helpers handle rate-limiting (`PORTSCAN_RATE_PER_SEC`) and the
per-IP cap (`PORTSCAN_MAX_DIALS_PER_IP`) — bypassing them breaks the
guarantees the scan engine relies on.

## Result fields

```go
type Result struct {
	Protocol     string
	Banner       []byte
	Fingerprint  *Fingerprint
	HTTPResponse *HTTPResponse   // set only by http.go and modules that speak HTTP
	TLSResult    *TLSResult      // set when the probe captured a cert
	Components   map[string]any  // free-form jsonb sidechannel
	AuthRequired bool
	RiskFactors  []string
	RiskScore    int             // 0–100; merged with derived heuristics
}
```

`RiskFactors` are short strings stored as a jsonb array on
`uv_service.risk_factors`. Keep them stable — they show up in dashboards
and are user-visible. Examples: `default_creds`, `outdated_version`,
`expired_cert`, `weak_cipher`.

## Conventions

- One protocol per file. Filename matches the protocol name in
  lowercase (`my_protocol.go`).
- Public probe entry point is unexported (`probeMyProtocol`) — only
  `init()` registers it.
- Helpers (`parseFooResponse`, `looksLikeFoo`) stay in the same file.
- No SQL. The probe returns data; the scanner pipeline writes it.
- No global state, no package-level mutex. Everything threadable.

## Linting

`golangci-lint run ./...` must pass. The repository enforces:

- `gofmt`, `gofumpt`, `goimports` with local prefix
  `github.com/yakushstanislav/UltraViolet`.
- `wsl_v5` and `nlreturn` for whitespace and return spacing.
- Author header on every `.go` file.

The pre-commit hook in `service-api/.githooks/pre-commit` checks the
staged files; CI runs the full suite.

## Tests

The project does not maintain automated tests
(`CLAUDE.md → Automated tests`). Do not add `*_test.go` files unless
the user explicitly requests them. Verify your probe against a real
service in a lab scan instead.

## Documentation

Append a row to [Service Protocols](/probes/service-protocols) in the
same commit. The `Documentation (Mandatory)` rule in `CLAUDE.md` makes
this a release-blocker.

## Wiring to risk scoring

If your protocol carries risk hints (e.g. default credentials hinted in
the banner, version known to be EOL), set `Result.RiskFactors` and a
non-zero `Result.RiskScore`. The scanner merges your contribution with
the version-derived risk; the final value lands in `uv_service.risk_score`
and shows up on the dashboard top-risk widget.

## Wiring to CVE matching

The matcher reads `uv_service_fingerprint.product` and `.version` and
joins to `uv_cve_cpe`. To get matches:

- Use the **canonical CPE vendor/product name** for
  `Fingerprint.Product` — check `uv_cpe_product_map` (seeded in
  `1_initial_schema.up.sql`) for
  the canonical form. If your product is missing from the map, add a row
  to `uv_cpe_product_map` in a follow-up migration.
- Always set `Confidence` honestly — the matcher uses it to decide
  whether to attempt version-less joins.
