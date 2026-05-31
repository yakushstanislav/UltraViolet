# Quick Tour

This walk-through covers the typical first-day workflow: launch a small
scan, browse results, save a search, and set up an alert.

## 1. Launch your first scan

1. Open the **Scans** page from the sidebar.
2. Click **New scan**.
3. Fill in the form:
   - **Name** — short descriptor (e.g. `Lab perimeter`).
   - **CIDR** — a small range you control, such as `192.0.2.0/29` (8 hosts).
   - **Ports** — pick a preset (e.g. `Web` for 80/443/8080/8443, or `Top 100`).
   - **Mode** — start with `slow` for a careful first run. Switch to `fast`
     once you trust your environment. See
     [Modes & Strategies](/scanning/modes-and-strategies).
   - **Strategy** — `sequential` walks the CIDR in order; `random`
     samples the IPv4 pool randomly. Use `sequential` for small known ranges.
4. Submit. The scan status moves from `PENDING` → `RUNNING` and the
   progress bar updates from the `/v1/ws` WebSocket feed.

Behind the scenes, `uv-scanner` claims the job, runs TCP connect on each
target, then dispatches per-port protocol probes — see
[Scan Lifecycle](/concepts/scan-lifecycle).

## 2. Inspect a host

When at least one service is found, open the **Search** page (or click an
IP in the scan detail view).

The host detail page shows:

- IP, hostname (PTR), GeoIP, ASN, first/last seen.
- Per-port services: protocol, banner, fingerprint (product + version),
  HTTP response (status, title, headers, body excerpt), TLS certificate
  chain (subject, issuer, SANs, JARM hash).
- **Related hosts**: other IPs that share the same ASN, country, or TLS
  certificate fingerprint.
- **Timeline**: every `service_change_event` for this host.
- For RTSP/ONVIF services, action buttons to capture a snapshot or query
  ONVIF metadata (gated by `RTSP_SNAPSHOT_ENABLED` /
  `ONVIF_COMMAND_ENABLED`).

## 3. Search across all hosts

The **Search** page accepts free-text plus structured filters:

| Filter | Example |
|---|---|
| `port` | `port:443` |
| `country` | `country:NL` |
| `protocol` | `protocol:ssh` |
| `q` | full-text over banner, server header, title, body |

The query is parsed in `uv-api` and translated into PostgreSQL
`tsvector` matches plus `pg_trgm` LIKE for partial substrings — see
[Search Overview](/search/overview).

Export the current result set with the `Export CSV` action (server-side,
`format=csv`).

## 4. Save the search and add an alert

In **Search**, click **Save** to persist the current query as a saved
search. Saved searches show up in the sidebar and re-run on demand.

In **Alerts** (operator+ role), point a new rule at the saved search:

- **Channel** — `log` records the event only; `webhook` POSTs the
  matched service to a URL you provide.
- **Cooldown** — minimum seconds between events for the same host/port
  pair.

The background `alert` worker re-evaluates rules on a fixed interval —
see [Alert Rules](/alerts/rules).

## 5. Track changes between scans

Re-run the scan against the same CIDR. When it finishes, open it and look
at the **Delta** tab:

- **New** — services present now, absent in the previous scan.
- **Disappeared** — services present in the previous scan, absent now.
- **Changed** — services whose fingerprint, banner, or TLS data changed.

See [Delta Concept](/delta/concept) for how comparisons are computed.

## 6. Schedule recurring scans

For periodic monitoring, create a **Scan Schedule** with a cron
expression — see [Schedules](/scanning/schedules).

## Where to go next

- Inventory of all probe protocols → [Service Protocols](/probes/service-protocols).
- Production hardening before opening to other operators → [Production Checklist](/security/checklist).
- API integration → [API Overview](/api/overview).
