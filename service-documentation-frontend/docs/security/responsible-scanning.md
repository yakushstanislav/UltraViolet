# Responsible Scanning

UltraViolet is a fast, broad scanner. It can describe a network in
detail very quickly. That is useful when you own the network — and
potentially serious when you do not. This page is the operational
guide that goes alongside the technical controls.

## The contract

Scan only ranges you own or have written authorisation to scan. There
are no exceptions. The defaults in `.env.example` are meant for lab
use; production deployments must narrow them.

## Controls UltraViolet enforces

| Control | Where | Purpose |
|---|---|---|
| `SCAN_ALLOWED_CIDRS` | `.env` | Hard allowlist. A scan with a CIDR outside this set is rejected with `scan_policy_violation`. |
| `SCAN_MAX_HOSTS` | `.env` | Caps the host count per scan. |
| `SCAN_MAX_PORTS` | `.env` | Caps the port count per scan. |
| RBAC `operator` / `admin` | DB | Only operator+ can create scans. |
| Audit log | DB | Every scan creation is recorded with user + IP. |
| `ONVIF_LAB_CREDENTIAL_PROBE_ENABLED` | `.env` | Default password probing is admin-only and disabled by default. |

Tighten `SCAN_ALLOWED_CIDRS` to the actual IP space you own. The
default `0.0.0.0/0,::/0` is the laziest control failure mode — fix it
on day one of production.

## Controls outside UltraViolet

These are not enforced by the software but you should still adopt
them:

- **Written authorisation.** A scope document signed by the asset
  owner, naming the CIDRs, ports, and time windows. Keep it on file.
- **Notification.** Tell your security team the scan is happening.
  Tell the network team if your masscan / zmap rate may trigger
  alarms. Telling them after the fact is worse than asking
  permission.
- **Rate limits.** Use `slow` mode and the default
  `PORTSCAN_RATE_PER_SEC=5000` until you know the network can absorb
  more. ICS / OT networks may break at any rate — coordinate.
- **Time windows.** Schedule heavy scans for low-traffic windows. The
  schedule runner exists exactly for this.

## What probes do — and do not — do

UltraViolet probes are **read-only**. They open TCP connections, send
protocol-shaped greetings, read responses. They do not:

- Write commands that modify the target (no `INSERT` on databases, no
  `CREATE` on storage systems, no PUT on HTTP).
- Run authenticated actions unless the operator provided credentials
  (RTSP snapshot, ONVIF command).
- Exploit known vulnerabilities. Even when the CVE matcher fires a
  `match`, UltraViolet does not attempt the exploit.

The one exception is the **ONVIF lab credential probe**, which actively
tries default credentials. It is admin-only, disabled by default, and
gated behind multiple envs. Use it only against equipment you own in a
lab environment. Production cameras may lock out, log the attempts, or
phone home to vendor cloud — assume hostility from any
network-attached device you didn't build.

## Off by default

The features below are off in `.env.example` because they take outbound
calls or are intrusive:

- `FDNS_ENABLED` — recursive DNS queries to external resolvers.
- `CTLOGS_ENABLED` — crt.sh lookups.
- `RDAP_ENABLED` — WHOIS lookups.
- `ONVIF_LAB_CREDENTIAL_PROBE_ENABLED` — default-password probing.

Turning any of these on is fine in the right context; recognise that
you're taking a step from "passive observer of my network" to "actor
calling third-party services / brute-forcing devices".

## Logging your scans

Every scan creates an audit log entry at create time. The scan record
remains even after you delete the target host. If you need an external
paper trail (compliance, legal hold), pipe the audit log into your SIEM
(see [Audit Log](/admin/audit)).

## When something goes wrong

If a scan accidentally hit out-of-scope IPs:

1. Cancel the scan immediately
   (`POST /v1/scans/{id}/cancel`).
2. Note the scan id, the actor, and the CIDR.
3. Tell the affected party. Speed matters; silence after the fact
   reads as malice.
4. Tighten `SCAN_ALLOWED_CIDRS` so the same mistake can't repeat.
5. Review the audit log; the row tells you exactly which operator
   submitted the scan.

## Legal context

UltraViolet is software. The legality of any given scan is determined
by the jurisdictions of the operator, the target, and the network
path. The author / maintainers do not provide legal advice. If you
operate UltraViolet professionally, your organisation's legal team
should review the deployment posture.

## When the right answer is "don't"

- Scanning competitor / customer / partner networks without an explicit
  contract.
- "Pen-testing" your own personal devices on a network you do not own
  (e.g. a coffee-shop Wi-Fi).
- Demonstrating the tool against arbitrary internet targets.

The technical controls in this codebase make these uses harder, not
impossible. The intent of the project is defensive: discover and
inventory your own assets, see what an attacker would see, fix the
gaps.
