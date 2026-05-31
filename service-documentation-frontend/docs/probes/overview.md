# Probes Overview

A probe is a module that takes an open `(host, port, transport)` and
returns a structured fingerprint. The probe stack is what turns "port
443 is open" into "Nginx 1.25.3 with a Let's Encrypt cert chain, GeoIP
NL, ASN 14061, JARM `2ad2ad0002ad2ad22c42d42d000000…`".

## The pipeline

```
┌────────────────┐
│ Scan engine    │  native / masscan / zmap
│ "port is open" │  → emits (host, port, transport)
└────────┬───────┘
         │
         ▼
┌────────────────┐
│ Stack dispatch │  pick probe by port, scheme, or banner prefix
└────────┬───────┘
         │
         ▼
┌────────────────┐
│ Protocol probe │  ~100 modules, each speaking one protocol
│                │  + generic TCP banner grab for unknown ports
└────────┬───────┘
         │
         ▼
┌────────────────┐
│ Fingerprint    │  derive product / version / confidence
│ derivation     │  from headers, banner, TLS subject, favicon
└────────┬───────┘
         │
         ▼
┌────────────────┐
│ Fallback       │  generic banner when nothing matched
└────────────────┘
```

## What gets stored

After probing, the scanner writes:

- **Service** — protocol, banner, banner hash, risk score.
- **HTTP response** — status, headers, title, body, technologies,
  favicon hash (for web services).
- **TLS certificate** — subject, issuer, SANs, JARM, JA3S/JA4S (for
  TLS services).
- **Fingerprint** — product, version, confidence, components.

See [Data Model](/concepts/data-model) for the full picture.

## Concurrency

The scanner runs probes in a pool of `SCANNER_PROBE_WORKERS` (default
48). Each probe gets up to `PROBE_TIMEOUT` (default 5 s) and reads at
most `PROBE_MAX_BODY_BYTES` (default 256 KiB) from the wire. Long
responses are truncated, never fully buffered.

```bash
# tune for CPU-bound hosts
SCANNER_PROBE_WORKERS=96
PROBE_TIMEOUT=8s
PROBE_MAX_BODY_BYTES=524288
```

## HTTP backends

`PROBE_BACKEND=native` uses a custom HTTP client tuned for fingerprint
fidelity (raw TLS ClientHello, no automatic decompression, no automatic
redirect following beyond a hard cap). `PROBE_BACKEND=stdlib` falls back
to Go's standard HTTP client — useful when the native client trips a
downstream WAF that fingerprints non-standard clients.

The choice affects HTTP probes only; JARM always uses the native
ClientHello generator.

## UDP probes

After each TCP pass, the scanner runs the UDP modules listed in
`SCANNER_UDP_PROBE_PORTS` (default `53,161,123,5353,623`). UDP probes
do not have a discovery step — they send a service-specific datagram
and decide whether the host responded. Disable with
`SCANNER_UDP_PROBE_PORTS=""`.

## Where to read more

- [HTTP & TLS](/probes/http-and-tls) — the most-used probes, in depth.
- [Banner & Fallback](/probes/banner-and-fallback) — what happens when
  no protocol matches.
- [Service Protocols](/probes/service-protocols) — full inventory of
  every protocol probe, with default ports and extracted fields.
