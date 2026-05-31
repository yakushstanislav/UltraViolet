# Search Overview

Search is the workhorse of UltraViolet. Every host, service, banner, HTTP
body, TLS cert, and DNS record is indexed at scan time and queryable from
the Search page or `GET /v1/search`.

## Query model

A search has two parts:

1. **Filters** — structured constraints (`port`, `country`, `protocol`).
2. **Free text** — substring / tsvector match across banner, server
   header, page title, HTTP body, TLS subject, SANs, DNS records.

The two combine with `AND`. Free text is matched against the full-text
search index of banners and HTTP bodies, falling back to a substring
match when the term is not on a word boundary.

## URL parameters

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/search?port=443&country=NL&q=nginx&limit=50" | jq
```

| Param | Notes |
|---|---|
| `q` | Free-text query. |
| `port` | Comma-separated list. `port=80,443`. |
| `country` | ISO 3166-1 alpha-2 country code. Comma-separated. |
| `protocol` | High-level protocol name (`http`, `ssh`, `mysql`, …). |
| `title` | Match against the HTTP page title. |
| `body` | Substring match on the HTTP response body. |
| `risk_gte` | `risk_score >= N`. |
| `cve` | CVE id (or partial). |
| `limit`, `offset` | Pagination. `limit ≤ 200`. |
| `format` | `json` (default) or `csv`. |

### New filters (pivot / correlation)

These parameters mirror the pivot graph kinds and are round-tripped by saved
searches:

| Param | Notes |
|---|---|
| `jarm` | Exact JARM hash (62 hex chars). |
| `ja3s` | JA3S hash (hex, 8–64 chars). |
| `ja4s` | JA4S hash (max 64 chars). |
| `favicon_hash` | Murmur favicon hash (numeric). |
| `body_sha256` | HTTP body SHA-256 (64 hex chars). |
| `http_title` | Exact HTTP page title (max 512 chars). |
| `confidence_gte` | Filter on `host.confidence` (`0..1`). |

## What is searched

| Term | How |
|---|---|
| Banner | Full-text and substring indexes on the raw banner. |
| HTTP body | Full-text and substring indexes on the captured body. |
| HTTP title | Exact-match index plus body full-text. |
| TLS subject / issuer / SANs | Substring indexes on certificate fields. |
| DNS records | Substring index on DNS name and value. |
| Service fingerprint | Indexed by product and (product, version). |

If you need a search to be fast against tens of millions of rows, prefer
filters that hit btree indexes (`port`, `country`, `protocol`,
`risk_gte`) and pair them with a short `q`. A bare `q=admin` against the
whole estate scans every tsv document.

## Query parsing

The parser accepts both URL params and a single combined search bar.
The combined bar splits on whitespace and recognises `key:value`
tokens; everything else becomes part of `q`. Examples:

| Search bar | Parsed |
|---|---|
| `port:443 nginx` | `port=443`, `q=nginx` |
| `country:NL ssh root@` | `country=NL`, `q="ssh root@"` |
| `protocol:rtsp` | `protocol=rtsp` |
| `cve:CVE-2023-44487 risk_gte:80` | `cve=CVE-2023-44487`, `risk_gte=80` |
| `body:"Welcome to nginx"` | `body=Welcome to nginx` |

The `body:"…"` quoted form uses the trgm index for partial-string
match; the unquoted equivalent goes through tsv tokenisation.

## Result shape

```json
{
  "total": 12384,
  "limit": 50,
  "offset": 0,
  "results": [
    {
      "ip":            "198.51.100.42",
      "port":          443,
      "protocol":      "https",
      "country_code":  "NL",
      "asn":           14061,
      "ptr_hostname":  "web42.example.com",
      "fingerprint":   { "product": "nginx", "version": "1.25.3", "confidence": "high" },
      "risk_score":    45,
      "risk_factors":  ["outdated_version"],
      "last_seen":     "2026-05-17T08:31:12Z",
      "cve_count":     3
    },
    …
  ]
}
```

Open any result for the full host detail view
(`/hosts/{ip}` in the UI, [Host Details](/hosts/host-details)
in this guide).

## Performance tips

- Add `risk_gte` or `port` to narrow the candidate set before the
  tsvector match.
- For dashboards, prefer the dedicated
  [Dashboard endpoints](/dashboard/) over `/search?limit=200`. They
  are pre-aggregated.
- Long `q` strings (4+ words) hit the trgm path less efficiently than
  the tsv path. Use quoted phrases for substring intent.

## Roles

All three roles (`viewer`, `operator`, `admin`) can read the search
endpoint. Write operations (saved searches, alerts pointing at a query)
require `operator` or `admin`.
