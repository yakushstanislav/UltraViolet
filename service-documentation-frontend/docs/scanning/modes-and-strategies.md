# Modes & Strategies

A scan combines a **mode** (how aggressively to probe) and a **target
strategy** (in what order to walk the CIDR). They are independent — any
combination is valid.

## Modes

The mode picks a parameter profile for the scanner.

| Mode | Use when | Effects |
|---|---|---|
| `slow` | First runs against unfamiliar networks; production audits. | Lower `PORTSCAN_RATE_PER_SEC`, longer `PROBE_TIMEOUT`, full probe stack on every port. Safer against IDS / stateful firewalls. |
| `fast` | Routine sweeps of a known network. | Default `PORTSCAN_*` envs, default `PROBE_TIMEOUT`, full probe stack. Best throughput / fidelity trade-off. |
| `aggressive` | Lab environments only; quick triage. | Higher fan-out, lower per-probe timeouts, may drop a slow protocol probe on the fallback path. Expect more false negatives on lossy paths. |

The scanner reads the mode at claim time, overlays the per-mode
profile, and applies the result to its worker pool.

### Tuning the profiles

The defaults live in env-vars; you tune them globally per scanner:

| Variable | Default | Used by |
|---|---|---|
| `PORTSCAN_WORKERS` | 512 | Concurrency of TCP dials. |
| `PORTSCAN_RATE_PER_SEC` | 5000 | Token-bucket rate limiter on outgoing SYNs. |
| `PORTSCAN_TIMEOUT` | 2s | Per-dial timeout. |
| `PORTSCAN_MAX_DIALS_PER_IP` | 64 | Per-IP concurrency cap (avoids stateful-firewall SYN drops). |
| `SCANNER_PROBE_WORKERS` | 48 | Per-service probe parallelism. |
| `PROBE_TIMEOUT` | 5s | Per-probe budget. |
| `PROBE_MAX_BODY_BYTES` | 262144 | Cap on captured HTTP body / banner. |
| `PROBE_JARM_ENABLED` | true | JARM TLS fingerprinting. |
| `SCANNER_UDP_PROBE_PORTS` | `53,161,123,5353,623` | UDP probe pass after each TCP scan. |

Set `PROBE_BACKEND=stdlib` to force the Go stdlib HTTP client for HTTP
probes — useful when the `native` backend trips a downstream WAF. The
`native` backend reuses connections more aggressively but exposes a
different TLS ClientHello surface.

## Target strategies

| Strategy | Use when | How it walks the CIDR |
|---|---|---|
| `sequential` | Small / medium known ranges (most cases). | IPs in numeric order, no skips. |
| `random` | Internet-scale sampling. | Shuffled pool drawn exclusively from the IPv4 entries of `SCAN_ALLOWED_CIDRS`. |
| `country` | Geographic sampling by country. | Random IPs drawn from IPv4 prefixes attributed to the given country in the GeoIP database. |

For `random`:

- IPv6 entries in the allowlist are ignored — masscan and zmap are
  IPv4-only, and the native engine follows the same rule for
  consistency.
- The pool is the **intersection** of the requested CIDR and
  `SCAN_ALLOWED_CIDRS`. If they do not overlap, the scan is rejected
  with `scan_policy_violation`.
- `host_limit > 0` is honoured (stops after N hosts).

For `country`:

- Requires a GeoIP database configured at startup (`GEOIP_CITY_PATH`). If
  no database is loaded, country scans are rejected at creation time.
- The `country` field must be an ISO-3166-1 alpha-2 code (e.g. `US`, `DE`).
- `host_limit > 0` is required — there is no CIDR ceiling, so an
  explicit limit prevents unbounded sampling.
- Only the `slow` engine (native TCP-connect) is supported; masscan and
  zmap require a CIDR input that the country strategy does not provide.

`sequential` is fully deterministic; rerunning the same scan touches
hosts in the same order. `random` and `country` re-seed on every run.

## Choosing a combination

| Goal | Mode | Strategy |
|---|---|---|
| Daily change tracking on a /24 you own | `fast` | `sequential` |
| First-time audit of a /16 acquired in a merger | `slow` | `sequential` |
| Sampling exposed RDP across a /8 lab | `fast` | `random` with `host_limit=2000` |
| Quick triage of a single IP | `aggressive` | `sequential` (CIDR `x.y.z.w/32`) |
| Geographic exposure snapshot for a country | `slow` | `country` with `country=US` and `host_limit=5000` |

## Engine vs mode

The engine (native / masscan / zmap) is orthogonal. You can run
`fast + masscan` to get masscan's discovery speed combined with
UltraViolet's probe stack. See [Engines](/scanning/engines) for the
trade-offs.
