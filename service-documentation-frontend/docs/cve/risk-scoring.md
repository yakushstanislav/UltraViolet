# Risk Scoring

Every service carries a `risk_score` between 0 and 100. The dashboard
tile, the search filter (`risk_gte`), and the alert default ordering all
read from this score. This page explains where the number comes from.

## Inputs

```
            ┌─────────────────────────┐
            │ Probe contributions     │  risk hints from the protocol probe
            └────────────┬────────────┘
                         │
                         ▼
            ┌─────────────────────────┐
            │ Version-derived risk    │  CVE matches (CVSS, EPSS, KEV)
            └────────────┬────────────┘
                         │
                         ▼
            ┌─────────────────────────┐
            │ TLS heuristics          │  expired cert, deprecated cipher
            └────────────┬────────────┘
                         │
                         ▼
            ┌─────────────────────────┐
            │ Exposure heuristics     │  RDP / VNC / MSSQL / ICS on a public IP
            └────────────┬────────────┘
                         │
                         ▼
                  Final risk score (0–100)
                  + structured risk factors
```

The final value is **not** a simple sum — the merger applies caps,
floors, and a confidence weighting so that one noisy signal doesn't
dominate.

## Per-CVE risk contribution

When a service has matched CVEs, the per-CVE contribution is:

```
contribution = CVSS_v3_score × weight(match_reason, confidence) × kev_multiplier × epss_multiplier
```

| Factor | Range | Notes |
|---|---|---|
| `CVSS_v3_score` | 0–10 | Falls back to v2 if v3 is missing. |
| `weight(match_reason, confidence)` | 0.3–1.0 | Exact version + high confidence = 1.0; banner-only + low = 0.3. |
| `kev_multiplier` | 1.0 or 1.4 | 1.4 when the CVE is in the CISA KEV catalog. |
| `epss_multiplier` | 1.0 + min(0.5, epss × 0.5) | Up to 1.5 for CVEs with EPSS near 1.0. |

The top three contributing CVEs are merged with diminishing returns
(the highest counts in full, the second at 70 %, the third at 40 %).
This prevents a pile of low-CVSS CVEs from pushing a service above the
actually-dangerous ones.

## TLS heuristics

| Factor | Contribution |
|---|---|
| Cert expired | +20 |
| Cert expires in < 14 days | +10 |
| Self-signed cert on TLS 443 | +5 |
| Deprecated TLS version (1.0 / 1.1) | +10 |
| Weak cipher in the negotiated suite | +5 |

Each active heuristic adds a token to the structured risk factors list
(`expired_cert`, `deprecated_tls`, `weak_cipher`).

## Exposure heuristics

The merger applies a baseline for services that should rarely be
internet-facing:

| Protocol | Baseline |
|---|---|
| RDP | 30 |
| VNC | 30 |
| MSSQL / Oracle / PostgreSQL / MySQL | 25 |
| MongoDB / Redis / Memcached / Elasticsearch | 25 |
| IPMI | 35 |
| ONVIF + default-creds factor | 50 |
| Modbus / BACnet / DNP3 / S7Comm | 40 |
| SMB | 20 |

These baselines apply only when the host's GeoIP reports a public
(non-RFC1918, non-CGNAT) address. On private ranges the baselines are
zeroed — internal RDP is not the same risk as internet RDP.

## Probe contributions

A probe can set a risk score and risk factors directly. The merger
trusts the value but caps individual probe contributions at 30 to keep
one noisy probe from dominating.

Examples in shipped probes:

- **RTSP** adds `default_creds` and +15 when a stream is reachable
  anonymously.
- **Redis** adds `unprotected_redis` and +30 when the server accepts
  commands without auth.
- **MongoDB** adds `unauthenticated_mongo` and +30 on the same pattern.
- **Elasticsearch** adds `unauthenticated_elasticsearch` and +25.

## Reading from the API

```bash
# Top 50 by risk
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/search?risk_gte=60&limit=50" | jq

# Dashboard risk breakdown
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/dashboard/risk" | jq
```

`/v1/dashboard/risk` returns histogram buckets (`0-19`, `20-39`,
`40-59`, `60-79`, `80-100`) plus the top contributing factors across
the estate.

## Roles

Read endpoints (`/search?risk_gte=`, `/dashboard/risk`,
`/services/{id}/cves`) — any authenticated role. The risk scorer
runs inside the scanner; there is no operator-facing knob.

## When the score looks wrong

- **Fingerprint confidence is low** — if the service was matched as
  `confidence = low`, CVE weights are 0.3. Improve the fingerprint by
  ensuring the product name has a canonicalisation entry in the CVE
  pipeline.
- **Probe contributing wrong factor** — check the host detail page for
  the active risk factors and cross-reference with the probe's
  expected output.
- **GeoIP misclassified** — internal subnets are intentionally
  de-weighted. Refresh the GeoIP database if a public IP is wrongly
  flagged as private (see [GeoIP](/deployment/geoip)).
