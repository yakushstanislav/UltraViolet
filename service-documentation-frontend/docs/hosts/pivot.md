# Pivot graph

The pivot graph shows every host and service that shares a correlation
artifact — TLS fingerprint, JARM, JA3S/JA4S, favicon hash, HTTP body hash, or
exact page title.

## Opening a pivot

On the [host detail](/hosts/host-details) page, click the **Pivot on this**
icon next to any supported artifact row. The UI navigates to
`/pivot/{kind}/{value}` and renders an interactive force graph.

Node colours:

- **Blue** — host (click to open `/hosts/{ip}`)
- **Grey** — individual service (port)
- **Accent** — the shared artifact at the centre of the graph

Service nodes show a risk-tinted halo when `risk_score` is elevated.

## Overflow

The API caps results at 500 matches (`truncated: true` in the response). Use
**Open in search** to continue investigation with the same filter encoded as
search query parameters.

## API

See [`GET /v1/pivot/{kind}/{value}`](/api/endpoints#pivot) in the endpoint
reference.

## Related

- [Related hosts](/hosts/related-hosts) — paginated peer list (cert / JARM /
  favicon only; kept for table workflows)
- [Search](/search/overview) — extended filters for all pivot kinds
