# Related Hosts

`GET /v1/hosts/{ip}/related` returns other IPs that share at least one
fingerprint-class discriminator with the target. The endpoint is the
foundation of the "pivot" workflow: start with one host, find everything
that looks like it. For a force-graph view across all artifact kinds (JA3S,
body hash, page title, …), use the dedicated [Pivot graph](/hosts/pivot)
(`GET /v1/pivot/{kind}/{value}`).

## Discriminators

The handler evaluates three independent axes in parallel and merges
them into a single flat list. Each row carries a `reason` so the UI can
group or filter:

| Reason | Match rule | Source |
|---|---|---|
| `cert_fingerprint` | Any `uv_tls_certificate.fingerprint_sha256` from the source host appears on another host | TLS cert table |
| `jarm` | Same `uv_tls_certificate.jarm_fingerprint` | TLS cert table |
| `favicon_hash` | Same `uv_http_response.favicon_hash` | HTTP response table |

The source host itself is excluded from the result.

## Query parameters

| Param | Type | Default | Constraints |
|---|---|---|---|
| `page` | uint | `1` | `>= 1` |
| `limit` | uint | `10` | `1..100` |

Pages are 1-indexed. Bad input returns `400 invalid_argument`.

## Response shape

```json
{
  "items": [
    {
      "ip": "198.51.100.42",
      "reason": "cert_fingerprint",
      "value": "9f86d081884c…",
      "country_code": "NL"
    },
    {
      "ip": "198.51.100.43",
      "reason": "jarm",
      "value": "27d40d40d29d40d…",
      "country_code": "DE"
    }
  ],
  "page": 1,
  "limit": 10,
  "total": 24
}
```

`total` is the count across all pages and is computed before
slicing. `country_code` is omitted when unknown.

## When to use it

- **Pivot from a hot IP**: you found one exposed service, find every
  other host using the same TLS cert or favicon.
- **Identify shared infrastructure**: a single cert or JARM signature
  across thousands of IPs is a classic "cloud provider front" signal.
- **Reduce alert noise**: when an alert fires, page through related to
  decide if the issue is a single misconfigured host or a fleet-wide
  pattern.

## Performance

The three axes are unioned inside one Postgres CTE; the same CTE backs
both the `COUNT(*)` query and the paged `SELECT`. Each axis is backed
by a btree index on its respective hash/fingerprint column, so cost
scales with the number of source matches rather than the full host
table.

To inspect everything in the same ASN (a different relation than this
endpoint covers) do a regular search:

```bash
curl -s "$API/v1/search?asn:14061" -H "authorization: bearer $TOKEN"
```

## UI

The Related hosts panel on the Host page renders the current page as a
flat table with one row per match. The pager (Prev / Next) appears only
when `total > limit`.

## Roles

`GET /v1/hosts/{ip}/related` — any authenticated role.
