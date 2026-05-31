# Overview

UltraViolet is a self-hosted infrastructure scanner — a Shodan-style tool that
runs on your own hardware, against networks you own or are authorised to scan.
It combines a TCP connect scanner, deep protocol probes, TLS and JARM
fingerprinting, GeoIP enrichment, CVE matching, and a PostgreSQL-backed query
layer behind a single REST API and a React UI.

## What it does

- **Discovers** open TCP/UDP services on configurable CIDR ranges, with the
  native scanner, masscan, or zmap as the discovery engine.
- **Probes** ~100 protocols (HTTP, TLS, SSH, FTP, SMTP, POP3/IMAP, RDP, VNC,
  databases like MySQL/PostgreSQL/Oracle/MSSQL/MongoDB/Redis, queues like
  Kafka/AMQP/NATS/MQTT, ICS/SCADA like Modbus/BACnet/DNP3/IEC104/S7Comm/ENIP,
  IoT like ONVIF/RTSP/AirPlay/Chromecast, identity like LDAP/IPMI, healthcare
  like DICOM/HL7, and many more).
- **Extracts** banners, server headers, page titles, HTTP bodies (with
  full-text indexing), TLS certificate chains, JARM and JA3S/JA4S
  fingerprints, technology stacks, favicon hashes, robots.txt, security.txt.
- **Enriches** every host with reverse DNS, GeoIP, ASN, and optional forward
  DNS / CT-log discovery.
- **Matches** discovered services to CVEs from a local NVD mirror, augments
  them with CISA KEV (Known Exploited Vulnerabilities) and FIRST EPSS
  (Exploit Prediction Scoring System).
- **Tracks** changes between scans of the same target — surfaces new,
  disappeared, and changed services as a delta, with WebSocket realtime
  events.
- **Alerts** on saved searches, with cooldown windows and log/webhook
  delivery.

## What it does not do

- It is not a vulnerability scanner that actively exploits flaws — the only
  credential-probing feature (`onvif-lab-credential-probe`) is explicitly
  scoped to lab environments and is admin-only.
- It is not a network mapper — there is no Layer-2 discovery, no SNMP walk
  beyond the protocol probe, no agent.
- It is not a multi-tenant SaaS — every deployment is single-tenant and runs
  inside its own Docker Compose stack.

## Components

| Service | Role | Image |
|---|---|---|
| `uv-api` | REST API, WebSocket events, Prometheus metrics, JWT auth, scan orchestration | `${UV_REGISTRY}/uv-api` |
| `uv-scanner` | Worker that claims scan jobs and runs the probe pipeline | `${UV_REGISTRY}/uv-scanner` |
| `service-frontend` | React 19 + Vite SPA + nginx that proxies `/api` and `/realtime` to `uv-api` | `${UV_REGISTRY}/uv-frontend` |
| `postgres` | PostgreSQL 16 with pg_trgm + tsvector indexes for full-text search | `postgres:16-alpine` |
| `uv-documentation` | This documentation site (opt-in via `docs` compose profile) | `${UV_REGISTRY}/uv-documentation` |

See [Architecture](/concepts/architecture) for how the pieces connect at
runtime.

## When to use UltraViolet

- Continuous discovery of your own internet-facing perimeter, with diffing.
- Internal network inventory for compliance reporting.
- Asset and vulnerability correlation in an air-gapped environment — the
  offline archive ships the CVE seed and all images locally.
- Tracking exposure of a specific protocol family (ICS, IoT, mail, databases).

## When **not** to use it

- Scanning ranges you do not own or have written authorisation to scan.
- Active exploitation or post-exploitation — UltraViolet is read-only by
  design; the only exception is the lab credential probe (admin-only, gated
  behind `ONVIF_LAB_CREDENTIAL_PROBE_ENABLED`).

Next: [Installation](/getting-started/installation).
