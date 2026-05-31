# Attack-Surface Score

Every host in UltraViolet carries a 0..100 risk score that reflects two
independent dimensions:

```
Score = round(100 · (1 − exp(−k · P · I)))
```

- **P** ∈ [0, 1] — probability the host is compromisable in a 30-day window.
- **I** ∈ [0, 1] — impact if the host is compromised.
- **k** — calibration coefficient (default `4.0`, configurable via `uv_risk_policy`).

Buckets stay aligned with the UI tiers:

| Bucket    | Score range |
| --------- | ----------- |
| low       | 0–24        |
| medium    | 25–49       |
| high      | 50–74       |
| critical  | 75–100      |

## Probability (per service, unioned at the host)

The probability that a single service is compromisable is decomposed into seven
independent channels. Each channel maps observed signals into `p_i ∈ [0, 1]`;
the per-service probability is the union of all channels (with a top-3 union
inside the KEV and EPSS channels for diminishing returns), then attenuated by a
half-life decay on `last_seen`:

| Channel             | Signals                                                                  |
| ------------------- | ------------------------------------------------------------------------ |
| `kev`               | `uv_service_cve.kev_added_at`, KEV age decay                             |
| `epss`              | `epss_score`, `cvss_score`, KEV-age anchored decay                       |
| `exposure`          | port bucket + protocol family looked up in `uv_risk_protocol_prior`      |
| `auth`              | fingerprint `auth_required`, `anonymous`, default-credentials detection  |
| `crypto`            | TLS expired / weak cipher / weak protocol / self-signed / SSH weak kex   |
| `app_hygiene`       | HSTS / CSP / X-Frame / X-CT-Options / Referrer-Policy / EOL tech stack   |
| `network_position`  | shared subnet / ASN / cert / favicon / JARM / tech (Phase 6 graph)       |

The host probability is the union over all the host's services capped at 0.99:

```
P_host = 1 − Π_services (1 − P_service)
```

Five medium-risk services therefore produce a higher `P_host` than a single
medium-risk service — exactly because an attacker has more parallel attack
avenues to pick from.

## Impact (per host)

Impact is the *consequence* of compromise, independent of vulnerabilities:

```
I_host = clamp01(
    untagged_impact_baseline
  + w_blast      · blast_radius(host)
  + w_lateral    · lateral_potential(host)
)
```

Weights live in `uv_risk_policy` and default to `w_blast = 0.15`,
`w_lateral = 0.20`, on top of an `untagged_impact_baseline` of `0.4`.
`confidence` is capped at `0.55`.

## Confidence

A confidence value in `[0, 1]` is persisted next to every score. It is the
mean of four sub-meters and is rendered as a ring around the numeric score in
the UI:

| Meter              | What it measures                                                  |
| ------------------ | ----------------------------------------------------------------- |
| `completeness`     | how many of (banner, TLS, HTTP headers, fingerprint, CVE) we have |
| `recency`          | bounded half-life decay of `last_seen`                            |
| `signal_quality`   | direct evidence (KEV flag set) vs inferred (auth state unknown)   |
| `tag_completeness` | reserved — fixed at the untagged floor (asset tagging removed)     |

## Temporal decay

A single helper (`internal/pkg/risk/decay/HalfLifeDecay`) is applied to every
time-sensitive input. Defaults from `uv_risk_policy`:

| Source        | Half-life | Floor |
| ------------- | --------- | ----- |
| KEV age       | 365d      | 0.20  |
| EPSS age      | 90d       | 0.30  |
| `last_seen`   | 30d       | 0.30  |
| TLS findings  | 60d       | 0.30  |

The floor prevents very old evidence from collapsing to zero — a five-year-old
KEV CVE is still real exploit knowledge.

## Persistence

| Table                       | Purpose                                                      |
| --------------------------- | ------------------------------------------------------------ |
| `uv_host`                   | per-host `risk_score`, `probability`, `impact`, `confidence`, `risk_factors` JSON |
| `uv_service`                | per-service `risk_score`, `probability`, `confidence`, `risk_factors` JSON |
| `uv_host_risk_snapshot`     | timeline rows appended on each recompute (Phase 3 trends)    |
| `uv_service_risk_snapshot`  | per-service timeline                                         |
| `uv_risk_protocol_prior`    | per-protocol exposure baselines (operator-tunable)           |
| `uv_risk_policy`            | weights, decay half-lives, `k` coefficient                   |

`risk_factors` carries the full explainable payload — channel `p_i`, impact
component contributions, confidence sub-meters — and is returned verbatim by
`GET /v1/hosts/{ip}/risk-explain`.

## Signal sources

Each probability channel is fed by a dedicated repository. The
`services/risk/signals.Collector` batches every per-host load into one
query per repository so a host with N services costs O(1) queries (not O(N)):

| Channel             | Repository / Table                               | What it reads                                                                                                   |
| ------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------|
| `kev` / `epss`      | `cvematch` (`uv_service_cve`)                    | per-service CVE list with `cvss_score`, `epss_score`, `kev_added_at`                                            |
| `exposure`          | `uv_risk_protocol_prior`                         | `(port_bucket, protocol_family)` baseline                                                                       |
| `auth`              | `servicefingerprint` (`uv_service_fingerprint`)  | `AuthRequired`, `Anonymous`, `Role` (default-credentials marker)                                                |
| `crypto`            | `tlscertificate` (`uv_tls_certificate`, `uv_tls_finding`) + `sshinfo` (`uv_ssh_info`) | expiry/expires-soon, weak protocol, weak cipher, self-signed, SSH weak kex                                      |
| `app_hygiene`       | `httpsecurity` (`uv_http_security`) + `httpresponse` (`uv_http_response`) | HSTS/CSP/X-Frame/X-CT/Referrer presence, `ServerHeader` version leak, technology-stack EOL match                |
| `network_position`  | (Phase 6) `uv_host_relation` + `uv_host_attack_path_score` | graph centrality / pivot-node score                                                                             |

Missing rows collapse to zero-value signals (the scorer treats them as
"no evidence"); this keeps the formula stable across hosts at different
enrichment depths and the `confidence` ring honestly reflects that.

## Recompute pathways

1. **CVE matcher** — after refreshing `uv_service_cve` for a service, the
   matcher calls `RiskService.AggregateForService`, which finds the host and
   recomputes.
2. **Background worker `host_risk_aggregate`** — periodic sweep over hosts with
   stale `risk_updated_at` (default every 15 minutes).
3. **Ingest hook** — the scanner pipeline triggers `AggregateForHost` after
   ingesting new probe results.

Each recompute writes a row to `uv_host_risk_snapshot` so the dashboard can
render trend lines; the retention worker prunes older than
`RISK_EVENT_RETENTION_DAYS` (default 180d).
