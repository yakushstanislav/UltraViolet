# TLS Certificates

Every successful TLS handshake stores a leaf certificate plus any
intermediate certificates the server sent. The Host page renders the
leaf + chain in a single card per service.

## Leaf certificate

```json
{
  "service_id":          1234,
  "subject":             "CN=*.example.com,O=Example Inc,L=Amsterdam,C=NL",
  "issuer":              "CN=R3,O=Let's Encrypt,C=US",
  "fingerprint_sha256":  "9f86d081884c…",
  "not_before":          "2026-02-14T00:00:00Z",
  "not_after":           "2026-05-15T23:59:59Z",
  "sans":                ["example.com", "*.example.com"],
  "jarm_fingerprint":    "2ad2ad0002ad2ad22c42d42d…",
  "ja3s_hash":           "abc123…",
  "ja4s_hash":           "t13d1715h2_…"
}
```

The leaf is shown with:

- **Subject** and **Issuer** decoded into named lines.
- **Validity** badge (`active` / `expiring soon` / `expired`).
- **SANs** as a chip list — each chip links back to a search for that
  hostname.
- **JARM / JA3S / JA4S** with copy-to-clipboard buttons. Click a JARM
  to pivot to every other IP with the same fingerprint.

## Chain

Chain certificates are ordered by position. Position 1 is the first
intermediate the server sent, 2 the next, etc.

```json
[
  { "chain_position": 1, "subject": "CN=R3, …", "issuer": "CN=ISRG Root X1, …", "fingerprint_sha256": "…" },
  { "chain_position": 2, "subject": "CN=ISRG Root X1, …", "issuer": "CN=DST Root CA X3, …", "fingerprint_sha256": "…" }
]
```

The UI renders the chain as a vertical list, top = server, bottom = root
candidate. A missing root is not an error — most servers do not send the
root certificate.

## Fingerprints across hosts

Subject and SAN indexes make hostname-based pivots fast:

```bash
curl -s "$API/v1/search?q=%22*.example.com%22" \
  -H "authorization: bearer $TOKEN"
```

For JARM pivots, the dashboard offers a dedicated widget that groups
services by JARM. For ad-hoc pivots, use the search bar:

```
jarm:2ad2ad0002ad2ad22c42d42d…
```

(The `jarm:` token is recognised by the search parser when present.)

## JARM, JA3S, JA4S

| Hash | What it captures | Cost |
|---|---|---|
| JARM | 10 hand-crafted ClientHellos hashed together — stable across reboots, sensitive to TLS stack config | 10 extra handshakes per TLS service |
| JA3S | One ServerHello hash — cipher, extension list, EC curves | 0 extra (piggybacks on the normal probe) |
| JA4S | Newer JA-series hash with TLS 1.3 support and salted bucket prefixes | 0 extra |

JARM is gated by `PROBE_JARM_ENABLED` (default `true`). Disable it on
very large fleets where the per-host cost adds up. JA3S/JA4S are always
captured when a handshake succeeds.

## Chain capture details

The chain is captured straight from the wire — what the server sent in
its Certificate handshake message, in order. UltraViolet does **not**
fetch missing intermediates from AIA links; rebuilding the path is the
responsibility of whoever consumes the data.

For PKI auditing, the chain data lets you find:

- Self-signed issuers (`subject = issuer` on chain position 0).
- Chains that include known compromised roots.
- Chains that include weird intermediates ("Lenovo Superfish", etc.).

## Validity tracking

`not_before` and `not_after` are stored as `timestamptz`. The
`expiring_soon` badge on the UI lights up when `not_after - now() < 30
days`. The data is also surfaced on the dashboard's risk widget when an
expired or near-expired cert is the highest-risk asset.

## Trust model

UltraViolet is a discovery tool, not a trust validator. It captures
what was on the wire — it does not assert whether a chain is valid in
any specific trust store. Use the captured fingerprints to ask trust
questions externally (Censys, CT logs, your own pinning service).
