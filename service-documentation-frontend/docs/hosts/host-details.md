# Host Details

A host in UltraViolet is one IP address — IPv4 or IPv6 — observed by at
least one scan. `GET /v1/hosts/{ip}` returns the full structured view
that the Host page in the UI renders.

## Request

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/hosts/198.51.100.42" | jq
```

The `{ip}` path parameter accepts IPv4 dotted-quad and IPv6 colon
notation. The handler normalises both and looks the row up by `inet`
column — case and bracket placement do not matter.

## Response

```json
{
  "host": {
    "ip":               "198.51.100.42",
    "country_code":     "NL",
    "city":             "Amsterdam",
    "latitude":         52.3676,
    "longitude":        4.9041,
    "asn":              14061,
    "asn_organisation": "DigitalOcean, LLC",
    "ptr_hostname":     "web42.example.com",
    "first_seen":       "2026-01-04T10:11:22Z",
    "last_seen":        "2026-05-17T08:31:12Z",
    "risk_score":       87,
    "risk_factors":     [ { "code": "kev_present", "label": "1 KEV-flagged CVE", "weight": 8 } ],
    "risk_updated_at":  "2026-05-17T08:35:00Z"
  },
  "services": [ /* open services (port, transport, protocol, banner, risk) */ ],
  "tls":      [ /* TLS certificates per service */ ],
  "http":     [ /* HTTP response per web service */ ],
  "ssh":      [ /* SSH details per SSH service */ ],
  "smtp":     [ /* SMTP details per mail service */ ],
  "dns":      [ /* DNS records */ ],
  "fingerprints": [ /* product/version fingerprints per service */ ],
  "cves":     { /* per-service CVE summaries */ }
}
```

The handler joins on `host_id` and returns everything in one round-trip
to make the detail page snappy. Heavy fields (HTTP body, raw TLS bytes)
are returned as-is — the body has already been capped at
`PROBE_MAX_BODY_BYTES` at probe time.

## What you see in the UI

The Host page is organised top-to-bottom:

1. **Header** — IP, PTR, country flag, ASN, first/last seen.
2. **Attack-surface score** — persisted host-level `risk_score` (0–100) with
   a **Why?** expander backed by `GET /v1/hosts/{ip}/risk-explain`. Factors
   are named bonuses anchored on the worst service score.
3. **Tabs**:
   - **Services** — port grid with status, banner preview, fingerprint,
     risk score, CVE count. See [Services & Banners](/hosts/services-and-banners).
   - **TLS** — cert chain, JARM, JA3S/JA4S, SAN expansion. See [TLS](/hosts/tls).
   - **Related** — other hosts that share cert / JARM / favicon. See
     [Related Hosts](/hosts/related-hosts) or open a [Pivot graph](/hosts/pivot)
     from any artifact row.
   - **Timeline** — every `service_change_event` for this host. See [Timeline](/hosts/timeline).
   - **DNS** — forward + reverse DNS records.
   - **CVEs** — flat list across all services, sorted by severity.

3. **Per-service actions** — visible on RTSP/ONVIF services:
   - **RTSP Snapshot** ([RTSP](/hosts/rtsp))
   - **ONVIF Command** ([ONVIF](/hosts/onvif))

4. **HTTP screenshot** — on HTTP services with a rendered thumbnail
   (`has_screenshot: true` in the API), a small square JPEG preview appears at
   the top of the **HTTP** section. Click the thumbnail to open a modal with
   the full image. The
   thumbnail is produced by the `uv-scanner` screenshot worker; it appears a
   few seconds after the probe finishes once the `chromium` container is
   running. Disable with `HTTP_SCREENSHOT_ENABLED=false` if you do not want
   the background render worker.

## GeoIP

GeoIP is populated by `uv-scanner` at insert time from MaxMind MMDBs in
`GEOIP_CITY_PATH` / `GEOIP_ASN_PATH` (or auto-detected in `./geoip` and
`/geoip`). Refresh the MMDBs monthly to keep ASN ownership and country
boundaries accurate — see [GeoIP](/deployment/geoip).

If both env paths are unset and no MMDB is found at the default
locations, the scanner logs a one-time warning at boot and leaves
country/ASN columns empty.

## PTR (reverse DNS)

When `RDNS_PTR_ENABLED=true` (default), the scanner runs a PTR lookup
after each TCP pass and stores the result as the host's PTR hostname. The
batch resolver runs `RDNS_GO_PROCESSES` parallel workers and times
out per host at `RDNS_TIMEOUT`. With `RDNS_RESOLVERS` set (default), PTR uses
the same retrying round-robin resolver pool as forward DNS instead of the
container's system resolver; leave it blank to fall back to the system resolver.

Forward DNS — A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV — runs when
`FDNS_ENABLED=true` (default). It resolves hostnames discovered from PTR, TLS
certificate SANs, and (optionally) Certificate Transparency logs, using the
`FDNS_RESOLVERS` pool round-robin. Truncated answers fall back to TCP, and
zone-level `NS`/`SOA` are cached per apex (`FDNS_CACHE_TTL`).

Each DNS record in the **DNS** tab carries:

- **Source** — `ptr`, `san`, `ct`, or `fcrdns`, showing where the name came from.
- **Forward-confirmed (FCrDNS)** — a shield marks records whose PTR hostname
  forward-resolves back to the scanned IP, distinguishing trustworthy reverse
  DNS from arbitrary PTR claims.

In the API response, each entry in the `dns` array carries `type`, `name`,
`value`, `source`, `forward_confirmed`, and `captured_at`.

## Roles

`GET /v1/hosts/{ip}`, `/related`, `/timeline` — any authenticated role.

`POST /v1/hosts/{ip}/rtsp-snapshot` and
`/onvif-command` — viewer and above (gated by feature flags below).

`POST /v1/hosts/{ip}/onvif-lab-credential-probe` — **admin only** and
gated by `ONVIF_LAB_CREDENTIAL_PROBE_ENABLED=true`.

## Mobile UI

On viewports **640px and below**, the Host page uses section tabs —
**Overview** (summary, map, DNS), **Services** (filter toolbar and service
panels), and **Related** (related-hosts table). RTSP and ONVIF tool blocks
are collapsed inside a **Protocol tools** disclosure by default so long
probe forms do not dominate the scroll. Use the bottom navigation **More**
sheet for Saved searches, Schedules, and admin routes.
