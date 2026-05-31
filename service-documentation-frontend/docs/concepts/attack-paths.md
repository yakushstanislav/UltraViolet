# Attack Paths

The attack-path subsystem turns the inventory into a graph: hosts are
nodes, edges encode "these two hosts share something an attacker could
pivot through". A host with many high-strength edges to critical
neighbours is itself dangerous — that gets folded back into the risk
score via the `network_position` probability channel and the
`lateral_potential` impact channel.

## Relation types

| Type               | Strength | Built from                                                      |
| ------------------ | -------- | --------------------------------------------------------------- |
| `shared_cert`      | 0.70     | Identical `uv_tls_certificate.fingerprint_sha256` across hosts. |
| `shared_subnet`    | 0.40     | `set_masklen(ip, 24)` equality (IPv4 /24 neighbours).           |
| `shared_favicon`   | 0.30     | Identical `uv_http_response.favicon_hash`.                      |
| `shared_asn`       | 0.20     | Identical `uv_host.asn`.                                        |
| `shared_jarm`      | reserved | JARM TLS fingerprint (planned).                                 |
| `shared_techstack` | reserved | Tech-stack overlap (planned).                                   |
| `shared_dns_root`  | reserved | Same apex domain (planned).                                     |

Edges with strength below `ATTACKPATH_RELATION_MIN_STRENGTH` (default
`0.10`) are dropped before persistence to keep `uv_host_relation` from
exploding.

## Centrality

For each host present in any relation:

```
degree     = count of incident edges (strength >= cutoff)
centrality = degree / max(degree across the graph)
pivot      = centrality · (1 + 0.1 · reachable_critical_count)
```

`reachable_critical_count` is the number of one-hop neighbours whose
`risk_score >= ATTACKPATH_CRITICAL_SCORE_CUTOFF` (default `75`). The
`pivot` term gives a small boost to hosts that bridge to critical assets.

`centrality` feeds the `network_position` probability channel (capped at
`0.40` contribution); `pivot` feeds `lateral_potential` in impact.

## Worker cadence

| Env var                            | Default | Purpose                                               |
| ---------------------------------- | ------- | ----------------------------------------------------- |
| `ATTACKPATH_ENABLED`               | `true`  | Master switch.                                        |
| `ATTACKPATH_INTERVAL`              | `6h`    | Tick interval.                                        |
| `ATTACKPATH_MAX_NODES`             | `50000` | Host count past which the worker skips the pass.      |
| `ATTACKPATH_RELATION_MIN_STRENGTH` | `0.10`  | Drop edges below this strength.                       |
| `ATTACKPATH_CRITICAL_SCORE_CUTOFF` | `75`    | `risk_score >= cutoff` → neighbour feeds pivot boost. |

The worker issues four batched aggregates — one per persisted relation
type — and self-joins through expression indexes (notably
`uv_host_subnet24_idx`) so the rebuild stays linear in matched pairs
rather than quadratic in host count.

## Performance budget

- Up to `MAX_NODES=50000` hosts → rebuild in single-digit seconds on a
  modest Postgres.
- Past the cap the worker logs a warn and skips the pass; the existing
  scores remain valid. Future work: incremental rebuild keyed on hosts
  whose `last_seen > worker.lastRunAt`.

Metrics:

- `uv_attackpath_graph_nodes` (gauge) — host count in the latest pass.
- `uv_attackpath_compute_duration_seconds` (histogram) — wall-clock time.

## API

| Method | Path                    | Role                                                               |
| ------ | ----------------------- | ------------------------------------------------------------------ |
| GET    | `/v1/attack-paths/{ip}` | V — returns the host's centrality + every relation anchored on it. |

Response includes:

- `score` — centrality + pivot breakdown for the focal host.
- `relations[]` — relation edges anchored on focal host (`src_host_id`, `dst_host_id`, `relation_type`, `strength`, `evidence`).
- `hosts[]` — host-id to IP map for all nodes used by `relations[]`, so the frontend can label/click neighbour nodes without extra lookups.

UI behavior:

- The header shows a pivot-strength chip (low/medium/high/critical bucket), a
  red "N critical reachable" pill when the focal host can reach critical
  neighbours, and a data-freshness line ("Updated N ago" from `computed_at`).
- KPI tiles (centrality, pivot, reachable critical, neighbours) are tinted by
  value so high-risk figures stand out at a glance.
- Relation-type filter chips carry a colour dot and a per-type count; an "All"
  chip clears the filter. The minimum-strength slider shows its current value
  and a "showing X of Y relations" summary; both narrow the graph in-place.
- The graph has zoom-in / zoom-out / fit-to-view / reset controls and auto-fits
  to the viewport once it loads. Node size reflects connection count, the focal
  host is ringed, and each neighbour is coloured by its strongest relation type
  (matching the filter-chip colours). Parallel edges between the same pair of
  hosts bow apart so every shared signal stays visible.
- Hovering a node previews its neighbourhood (incident edges stay lit, the rest
  dim); single-clicking selects it — the highlight sticks and the sidebar shows
  that host's details. Double-clicking a node, or the sidebar "Open this host's
  attack paths" button, pivots to that host as a new focal point.
- When filters or the strength threshold hide every relation, the graph shows a
  "no relations match" message with a "Clear filters" button rather than the
  empty-host message.
- Sidebar relation groups are sorted by strength with the strongest group
  auto-expanded; each edge shows a strength meter and its full evidence fields.
  The sidebar scrolls within the graph's height with a sticky "Relations"
  header, and the centrality / pivot / reachable-critical labels carry tooltips
  explaining each metric.
