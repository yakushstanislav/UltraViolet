# Remediation Recommendations

After every host recompute the risk service projects a short list of
remediation actions and persists them in
`uv_remediation_recommendation`. Each row carries the action code, a
human-readable label, the per-service probability reduction that would
result, and the projected score drop in score points.

## Candidate generation

`pkg/risk.RecommendForService` runs against the channel breakdown of one
service and emits these candidates:

| `action_code`             | Trigger                                                                | Expected `Δp`            |
| ------------------------- | ---------------------------------------------------------------------- | ------------------------ |
| `patch_cve`               | Per-CVE candidate when KEV-listed or `EPSS >= 0.20`.                   | `0.50 + 0.40·EPSS`, capped at `0.9` |
| `enforce_authentication`  | `p_auth >= 0.30` (no-auth / anonymous).                                | Current `p_auth - 0.05`  |
| `fix_tls_findings`        | `p_crypto >= 0.10` (expired / weak protocol / weak cipher / self-signed). | Full `p_crypto`        |
| `set_security_headers`    | `p_app_hygiene >= 0.05`.                                               | Full `p_app_hygiene`    |
| `close_management_port`   | `p_exposure >= 0.30` **and** port is a management surface (DB/RDP/broker/plaintext). | Full `p_exposure`     |

`Δscore` (in score points) is computed via the canonical
`100·(1-exp(-k·P))` mapping at the original and reduced `P` — the engine
hands the operator a directly-comparable number, not a probability.

## Lifecycle

Recommendations are **read-only**. There is no apply/dismiss action: on
every host recompute `ReplaceForHost` clears the host's rows and inserts
the freshly projected set, so the list always reflects the current
signals. To refresh the recommendations, re-scan the host.

## API

| Method | Path                                              | Role |
| ------ | ------------------------------------------------- | ---- |
| GET    | `/v1/hosts/{ip}/risk-recommendations?limit=20`    | V    |

The list is ordered by `expected_delta_score DESC, id ASC` — biggest
score reduction first.

## Metrics

`uv_remediation_recommendations_open` (gauge) — sampled by the
retention worker on each tick; counts persisted recommendations across
the inventory. A growing backlog signals rapid inventory growth or many
unaddressed findings.

## Tuning

The cutoffs (`recommendAuthCutoff`, `recommendCryptoCutoff`, …) live as
named constants in `internal/pkg/risk/recommend.go`. Lowering them
broadens recommendations (more noise); raising them narrows the list
(operators see only the loudest signals).
