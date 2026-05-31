---
layout: home

hero:
  name: UltraViolet
  text: Self-hosted infrastructure scanner
  tagline: Discover open services, fingerprint banners and TLS, match CVEs, alert on changes — all on your own hardware.
  actions:
    - theme: brand
      text: Get started
      link: /getting-started/overview
    - theme: alt
      text: View the API
      link: /api/overview
    - theme: alt
      text: Deploy
      link: /deployment/docker-compose

features:
  - title: Full-spectrum probing
    details: 100+ protocol probes (HTTP, TLS, SSH, databases, queues, ICS/SCADA, IoT, identity, media) on top of a TCP connect scanner with optional masscan/zmap acceleration.
  - title: Built-in CVE & risk pipeline
    details: NVD mirror with CISA KEV and EPSS enrichment. Services are matched to CVEs by fingerprint, version, banner, and CPE — with confidence levels.
  - title: Change tracking
    details: Every scan produces a delta against the previous run on the same target — new, disappeared, and changed services, with CSV export and real-time WebSocket events.
  - title: Query-based alerts
    details: Save a search, point an alert rule at it, choose log or webhook delivery. Cooldown windows keep noisy targets from drowning the channel.
  - title: RBAC and audit
    details: Three roles — viewer, operator, admin — with JWT auth, refresh rotation, configurable rate limits, and an append-only audit log.
  - title: Air-gap friendly
    details: Bundled offline archives include all images, CVE seed, and GeoIP MMDBs. Install with one command, no registry access required.
---

## Where to start

- **First-time setup** — [Installation](/getting-started/installation), then [Quick Tour](/getting-started/quick-tour).
- **You inherited a running instance** — start at [Architecture](/concepts/architecture) and [Scan Lifecycle](/concepts/scan-lifecycle).
- **You need to call the API** — [API Overview](/api/overview) and the full [Endpoints table](/api/endpoints).
- **You are deploying to production** — [Production Checklist](/security/checklist) and [Environment Reference](/deployment/env-reference).
