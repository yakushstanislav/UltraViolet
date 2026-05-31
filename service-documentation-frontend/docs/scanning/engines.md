# Engines

UltraViolet supports three TCP discovery engines. The engine controls how
open ports are found; the probe stack (HTTP, TLS, service-specific) runs
the same way regardless of engine.

| Engine | Throughput | Stealth | Privileges | Use when |
|---|---|---|---|---|
| `native` | medium | medium | none (TCP connect) | Default. Works everywhere. |
| `masscan` | very high | low | `NET_RAW` capability | Large CIDRs, sub-minute discovery passes. |
| `zmap` | very high | low | `NET_RAW` capability | Internet-scale sampling, single-port sweeps. |

The engine is chosen per-scan (`engine` field) — there is no global
default beyond `native`.

## `native`

Pure Go TCP connect scanner in `internal/pkg/portscan/`. Every dial is a
full TCP three-way handshake. The OS sees the scan as legitimate
connection attempts; the scanner sees `connection refused`, `i/o
timeout`, or a successful dial.

Pros:

- Runs without elevated privileges. Compose containers do not need
  `cap_add: NET_RAW`.
- Per-IP fairness via `PORTSCAN_MAX_DIALS_PER_IP` — avoids triggering
  stateful firewall SYN-flood mitigations.
- Token-bucket pacing via `PORTSCAN_RATE_PER_SEC`.

Cons:

- Slower than masscan/zmap at million-host scale.
- Visible to any decent IDS as a high-fan-out TCP connection pattern.

Recommended for: lab and corporate ranges, the daily monitoring case.

### Key envs

```bash
PORTSCAN_WORKERS=512
PORTSCAN_TIMEOUT=2s
PORTSCAN_RATE_PER_SEC=5000
PORTSCAN_MAX_DIALS_PER_IP=64    # 0 disables the per-IP cap
```

## `masscan`

UltraViolet shells out to a system-installed [masscan](https://github.com/robertdavidgraham/masscan)
binary (`MASSCAN_BINARY`, default `masscan`). The scanner parses
masscan's `-oJ` output and feeds discovered open ports into the same
probe pipeline as `native`.

Pros:

- Asynchronous SYN scanning at hundreds of thousands of pps.
- Single-pass discovery on huge CIDRs.

Cons:

- Requires `NET_RAW` and `NET_ADMIN` Linux capabilities on the scanner
  container (already wired in `service-env/docker-compose.yml`).
- Sends raw SYNs from the host's network namespace — uses the host's
  source IP, bypasses Docker's NAT.
- Cannot scan IPv6.
- Stateful firewalls and NICs without offload can drop SYNs at high
  rates → false negatives. Compensate with `MASSCAN_RETRIES`.

### Key envs

```bash
MASSCAN_BINARY=masscan
MASSCAN_RATE=3000           # packets per second
MASSCAN_RETRIES=2           # extra SYN sends per port
MASSCAN_WAIT_SECONDS=30     # cool-down before parsing results
MASSCAN_INTERFACE=          # explicit interface, blank = auto
MASSCAN_UNPRIVILEGED=false  # set to true to run masscan as non-root (degrades capability)
```

## `zmap`

UltraViolet shells out to [zmap](https://github.com/zmap/zmap)
(`ZMAP_BINARY`, default `zmap`). zmap is single-port per run, so the
scanner invokes it once per port in the scan's port list.

Pros:

- Higher peak throughput than masscan when a single port is targeted.
- Mature, widely audited.

Cons:

- Same capability requirements as masscan.
- Single-port per invocation → many invocations for a typical port set.
  Use `native` or `masscan` if you scan more than ~5 ports.
- IPv4-only.

### Key envs

```bash
ZMAP_BINARY=zmap
ZMAP_RATE=1000
ZMAP_COOLDOWN_SECONDS=8
ZMAP_INTERFACE=
```

## Choosing an engine

| Scenario | Engine |
|---|---|
| Anything under /20, mixed port sets, IPv6 in play | `native` |
| /16 or larger, ≤ 10 ports, IPv4-only | `masscan` |
| Single-port internet sample, IPv4-only | `zmap` |

`native` is the only engine that works against containers running
without `NET_RAW` — which is the recommended deployment posture for
shared / multi-tenant hosts. Granting `NET_RAW` to a container lets
it craft arbitrary packets from the host namespace; only enable it
when you own the host.

## UDP probing

Regardless of engine, the scanner runs a UDP probe pass after each TCP
scan against `SCANNER_UDP_PROBE_PORTS` (default
`53,161,123,5353,623` — DNS, SNMP, NTP, mDNS, IPMI). UDP probes have no
"discovery" step; the probe modules send a service-specific datagram
and decide whether the host responded.

Set `SCANNER_UDP_PROBE_PORTS=""` to disable the UDP pass.
