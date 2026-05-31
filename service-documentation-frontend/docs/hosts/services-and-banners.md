# Services & Banners

Every open port on a host is a row in `uv_service`. This page covers what
the row carries and how the UI presents it.

## Row shape

| Field | Meaning |
|---|---|
| `port`, `transport` | TCP/UDP and port number. |
| `protocol` | High-level protocol name (`http`, `ssh`, `mysql`, `modbus`, …). |
| `banner` | First bytes the server sent (capped at `PROBE_MAX_BODY_BYTES`). |
| `banner_hash` | SHA-256 of `banner` — used by the delta engine. |
| `risk_score` | 0–100. Composed of probe contributions and version-derived risk. |
| `risk_factors` | jsonb array of short tokens (`outdated_version`, `expired_cert`, `default_creds`, `weak_cipher`). |
| `last_seen`, `first_seen` | Timestamps; updated on every re-observation. |

The protocol-specific extras live in side tables — `uv_http_response`,
`uv_tls_certificate`, `uv_ssh_info`, `uv_smtp_info`,
`uv_service_fingerprint`. They are joined by `service_id` and surfaced
on the host detail page.

## Risk score

`risk_score` is the merged output of:

1. **Probe contributions** — protocol probes can set
   `Result.RiskScore` and `Result.RiskFactors` (e.g. RTSP probe sets
   `default_creds` when a known default port is anonymously reachable).
2. **Version-derived risk** — the scoring layer reads
   `uv_service_fingerprint.(product, version)` and walks the joined
   `uv_service_cve` rows. A CVSS-v3 base score is reduced by `confidence`
   and the matcher's `match_quality`.
3. **TLS heuristics** — expired certs, self-signed cert in production
   contexts, deprecated ciphers (TLS1.0 / 1.1 with no fallback).
4. **Exposure heuristics** — services that should rarely be public
   (RDP, MSSQL, VNC, IPMI, ICS) contribute a baseline.

The composite score is bucketed into the dashboard's risk breakdown and
backs the `risk_gte` search filter.

## Banner storage

Banners are stored raw. The tsvector on `banner_tsv` is generated from
the cleaned UTF-8 view; the trigram index on `banner` covers
substring search.

`banner_hash` is the **only** field the delta engine reads when
deciding whether a service "changed" — meaning a banner whose visible
text didn't move but whose whitespace did **will** show up as a change
(`uv_service_change_event.event_type = "changed"`). This is intentional;
banner whitespace is often a server-side build marker.

If you want to suppress that signal, dedupe on `banner_tsv` instead —
the search layer already does that.

## Fingerprints

`uv_service_fingerprint` has up to one row per service. See
[Probes — HTTP & TLS](/probes/http-and-tls#derived-fingerprints-derived-go)
for how it is built. Surfacing it on the UI:

- Product + version inline in the service row.
- Confidence chip (`high` / `medium` / `low`).
- A "view raw" disclosure that shows the `components` jsonb (SSH key
  algorithms, HTTP frameworks, TLS suites).

## SSH and SMTP detail tables

These two protocols get dedicated rows:

`uv_ssh_info`:

```json
{
  "server_version":   "OpenSSH_8.4p1 Debian-5+deb11u2",
  "host_key_type":    "ssh-ed25519",
  "host_key_fp":      "SHA256:abc…",
  "kex":              ["curve25519-sha256", …],
  "ciphers":          ["chacha20-poly1305@openssh.com", …],
  "macs":             ["hmac-sha2-256-etm@openssh.com", …]
}
```

`uv_smtp_info`:

```json
{
  "banner":           "220 mx.example.com ESMTP …",
  "ehlo_capabilities": ["PIPELINING", "STARTTLS", "AUTH PLAIN LOGIN"]
}
```

The trgm index on `uv_smtp_info.banner` makes searches like
`"q:Postfix"` fast.

## Per-service CVE list

`GET /v1/services/{id}/cves` returns every `uv_service_cve` row joined
to `uv_cve`:

```json
[
  {
    "cve_id":            "CVE-2023-44487",
    "summary":           "HTTP/2 Rapid Reset …",
    "cvss_v3_score":     7.5,
    "cvss_v3_severity":  "HIGH",
    "epss_score":        0.94,
    "is_kev":            true,
    "match_reason":      "product_version",
    "confidence":        "high"
  },
  …
]
```

`match_reason` and `confidence` come from the matcher — see
[CVE Matching](/cve/matching). The UI sorts by severity then EPSS
then KEV flag.
