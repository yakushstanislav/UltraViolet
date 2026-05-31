# HTTP & TLS

These two probes fire on almost every scan. They are the primary source
of fingerprint data for web-facing services.

## HTTP probe

The HTTP probe issues `GET /` to each web-speaking service. It runs on
the default web ports (80, 443, 8080, 8443, 8000, 8888, 7443, …) and on
any port where the generic banner module saw an HTTP-shaped first line.

| Captured field | Source |
|---|---|
| Status code | Final HTTP status after redirects |
| Server header | `Server:` response header |
| Page title | `<title>` text, HTML-decoded |
| Body | Response body up to `PROBE_MAX_BODY_BYTES` |
| Headers | Full response headers |
| Redirect chain | URLs walked while following redirects |
| Robots.txt | `/robots.txt` fetched in a side call |
| Security.txt | `/.well-known/security.txt` |
| Favicon hash | mmh3 hash of `/favicon.ico` (Shodan-compatible) |
| Technologies | Detected stack (web server, CMS, frameworks) |

### Redirect handling

The probe follows redirects up to a hard cap (5). Each hop is recorded
in the redirect chain. Cross-host redirects update the captured TLS
fingerprint (the leaf cert is taken from the final hop), but the
original IP/port remains the scan entry.

### Body truncation

`PROBE_MAX_BODY_BYTES` (default 256 KiB) is enforced at the wire — the
reader stops mid-stream when the cap is reached. Truncated bodies are
flagged in the stored metadata so the search layer can indicate the
truncation.

### Technology detection

The scanner runs a set of regex and HTML-attribute rules against
headers, body, and favicon hash. It produces entries like:

```json
{
  "Nginx":        {"version": "1.25.3"},
  "WordPress":    {"version": "6.4.3"},
  "Cloudflare":   {},
  "PHP":          {"version": "8.2.10"}
}
```

The rule set is intentionally small and conservative — every false
positive shows up as a CVE match later in the pipeline, so the bar for
adding a rule is "confident match, not just keyword".

### Favicon

The probe fetches `/favicon.ico`, mmh3-hashes the bytes, and stores the
hash. The hash matches Shodan's convention, so pivots like "every host
with this favicon" work across the two data sources.

## TLS probe

The TLS probe runs against any service that successfully completes a
TLS handshake — both well-known ports (443, 8443, …) and any port where
the engine observed a TLS-flavoured first byte.

| Captured field | Source |
|---|---|
| Subject / issuer | Leaf certificate distinguished names |
| SHA-256 fingerprint | Digest of the DER-encoded certificate |
| Validity window | `notBefore` / `notAfter` from the cert |
| Subject Alternative Names | SAN extension |
| JARM fingerprint | 10-probe TLS stack hash |
| JA3S / JA4S | Server-side TLS handshake hashes |
| Full chain | Intermediate certs in order |

### JARM (`PROBE_JARM_ENABLED`)

JARM ([Salesforce](https://github.com/salesforce/jarm)) sends 10
specially-crafted TLS ClientHellos and hashes the concatenated server
responses. The result is a stable fingerprint of the TLS stack
configuration. UltraViolet emits the JARM hash on every TLS service when
`PROBE_JARM_ENABLED=true` (default).

Use JARM to:

- Find every IP that runs the same TLS stack as a known C2 (pivot by
  hash).
- Detect TLS misconfigurations that change the JARM (e.g. cipher policy
  drift).

JARM has a per-host overhead of ~10 extra ClientHellos per TLS service.
Disable with `PROBE_JARM_ENABLED=false` if you scan very large or
ephemeral fleets where the overhead matters.

### JA3S / JA4S

JA3S and JA4S hash the server's ServerHello (cipher, extensions, EC
curves). They are cheaper than JARM (one handshake) and complement it
— JA4S is the newer, more discriminating variant. Both are populated on
every TLS handshake and are exposed in the host detail view.

### Chain capture

The probe captures every certificate the server sends in its TLS
Certificate message, in order. Each non-leaf certificate is stored
separately. This makes issuer-based pivots (`issuer:"Let's Encrypt"`)
fast.

## Derived fingerprints

After HTTP and TLS captures, the scanner derives a product / version
fingerprint:

| Input | Derived product/version |
|---|---|
| `Server: nginx/1.25.3` | `nginx 1.25.3` (high confidence) |
| Detected technology `Apache` | `Apache HTTPD` |
| Body contains `WordPress 6.x` | `WordPress 6.x` (medium confidence) |
| TLS subject `O=Synology`, port 5001 | `Synology DSM` (medium confidence) |

The confidence level and match quality feed the CVE matcher. See
[CVE Matching](/cve/matching) for how matches are computed.
