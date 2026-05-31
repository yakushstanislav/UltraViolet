# Risk Policies

The attack-surface risk score is fully parameterised. Every weight, decay
half-life, threshold and the global `k` coefficient lives in the
`uv_risk_policy` table — operators tune the model without a code release.

## Singleton row

There is exactly one row per deployment, identified by `name = 'default'`.
The seed migration inserts it with the values described in
[Attack-Surface Score](attack-surface-score.md). All scoring code reads the
row through an in-process cache (`services/risk/policy.Service`) with a TTL
of `RISK_POLICY_CACHE_TTL` (default `60s`).

| Column                        | Default    | Meaning                                                           |
| ----------------------------- | ---------- | ----------------------------------------------------------------- |
| `k_coefficient`               | `4.0`      | Constant in `Score = 100·(1-exp(-k·P·I))`.                        |
| `weight_blast`                | `0.15`     | Impact channel — service count / mgmt port density.               |
| `weight_lateral`              | `0.20`     | Impact channel — attack-path centrality.                          |
| `decay_kev_halflife_days`     | `365`      | KEV-listed CVE age half-life.                                     |
| `decay_epss_halflife_days`    | `90`       | EPSS forecast age half-life.                                      |
| `decay_recency_halflife_days` | `30`       | `last_seen` half-life for the recency multiplier.                 |
| `decay_tls_halflife_days`     | `60`       | TLS finding age half-life.                                        |
| `decay_*_floor`               | `0.2..0.3` | Lower bound for each decay multiplier (never below).              |
| `untagged_impact_baseline`    | `0.4`      | Base `I_host` applied to every host before blast/lateral.         |
| `untagged_confidence_cap`     | `0.55`     | Confidence is capped at this value.                               |
| `high_risk_threshold`         | `65`       | Service score above which the host gets the broad-exposure bonus. |

## API

| Method | Path              | Role | Purpose                                  |
| ------ | ----------------- | ---- | ---------------------------------------- |
| GET    | `/v1/risk/policy` | V    | Read the current policy (operator view). |
| PATCH  | `/v1/risk/policy` | A    | Overwrite the policy.                    |

`PATCH` invalidates the in-process cache so the next recompute reads the new
values. In a multi-pod deployment only the writing pod sees the new policy
immediately; other pods refresh at the next `RISK_POLICY_CACHE_TTL` window.

## UI workflow

Risk Policy is exposed as a settings list:

- a standard page header whose actions (**Reset to defaults**, **Revert
  unsaved**, **Save**) sit on the right, with an inline status pill
  (`unsaved changes` / `needs fixes`) shown only when relevant,
- grouped cards (coefficients, half-lives, floors, untagged behavior); each
  knob is a row — label and one-line description on the left, a compact numeric
  input (with a unit suffix where relevant) on the right,
- non-destructive comparison: a row whose value differs from the last saved
  policy is flagged with a marker, and **Revert** (restore last saved) /
  **Reset** (load defaults) both require confirmation before discarding edits,
- unload guard for unsaved changes.

## Calibration workflow

1. Pull current policy: `GET /v1/risk/policy`.
2. Adjust one knob at a time — usually `k_coefficient` (global scale) or a
   single impact weight.
3. `PATCH /v1/risk/policy` with the full object.
4. Wait for the next host recompute (or re-ingest a known host) and read the
   updated score via `GET /v1/hosts/{ip}/risk-explain`.
5. Compare to expectations; iterate.

## Per-protocol priors

`uv_risk_protocol_prior` holds the exposure baseline (`p_exposure`) per
`(port_bucket, protocol_family)` pair. The seed table:

```
database       any  0.50    mysql/postgres/mongo/redis/elasticsearch/couchdb
broker_cache   any  0.40    memcached/amqp/kafka/zookeeper
remote_desktop any  0.45    RDP/VNC
plaintext      any  0.35    ftp/telnet/smtp/pop3/imap/snmp/ldap/mssql/oracle
http           web  0.05    plain HTTP webserver
https          web  0.05    HTTPS webserver
other          any  0.10    everything else
```

Direct `UPDATE` plus `Invalidate` is the supported tuning path until a
dedicated admin endpoint lands (planned).
