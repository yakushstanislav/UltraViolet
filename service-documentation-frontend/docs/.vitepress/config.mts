import { defineConfig } from 'vitepress';

const sidebar = [
  {
    text: 'Getting Started',
    collapsed: false,
    items: [
      { text: 'Overview', link: '/getting-started/overview' },
      { text: 'Installation', link: '/getting-started/installation' },
      { text: 'First Login', link: '/getting-started/first-login' },
      { text: 'Quick Tour', link: '/getting-started/quick-tour' },
    ],
  },
  {
    text: 'Concepts',
    collapsed: false,
    items: [
      { text: 'Architecture', link: '/concepts/architecture' },
      { text: 'Data Model', link: '/concepts/data-model' },
      { text: 'RBAC & Authentication', link: '/concepts/rbac' },
      { text: 'Scan Lifecycle', link: '/concepts/scan-lifecycle' },
    ],
  },
  {
    text: 'Scanning',
    collapsed: false,
    items: [
      { text: 'Creating Scans', link: '/scanning/creating-scans' },
      { text: 'Modes & Strategies', link: '/scanning/modes-and-strategies' },
      { text: 'Managing Scans', link: '/scanning/managing-scans' },
      { text: 'Engines', link: '/scanning/engines' },
      { text: 'Schedules', link: '/scanning/schedules' },
    ],
  },
  {
    text: 'Probes',
    collapsed: false,
    items: [
      { text: 'Overview', link: '/probes/overview' },
      { text: 'HTTP & TLS', link: '/probes/http-and-tls' },
      { text: 'Banner & Fallback', link: '/probes/banner-and-fallback' },
      { text: 'Service Protocols', link: '/probes/service-protocols' },
    ],
  },
  {
    text: 'Search',
    collapsed: false,
    items: [
      { text: 'Overview', link: '/search/overview' },
      { text: 'Saved Searches', link: '/search/saved-searches' },
      { text: 'Export', link: '/search/export' },
    ],
  },
  {
    text: 'Hosts',
    collapsed: false,
    items: [
      { text: 'Host Details', link: '/hosts/host-details' },
      { text: 'Services & Banners', link: '/hosts/services-and-banners' },
      { text: 'TLS Certificates', link: '/hosts/tls' },
      { text: 'Pivot Graph', link: '/hosts/pivot' },
      { text: 'Related Hosts', link: '/hosts/related-hosts' },
      { text: 'Timeline', link: '/hosts/timeline' },
      { text: 'ONVIF', link: '/hosts/onvif' },
      { text: 'RTSP Snapshots', link: '/hosts/rtsp' },
    ],
  },
  {
    text: 'Delta',
    collapsed: false,
    items: [
      { text: 'Concept', link: '/delta/concept' },
      { text: 'Exports', link: '/delta/exports' },
    ],
  },
  {
    text: 'Alerts',
    collapsed: false,
    items: [
      { text: 'Rules', link: '/alerts/rules' },
      { text: 'Events', link: '/alerts/events' },
    ],
  },
  {
    text: 'CVE & Risk',
    collapsed: false,
    items: [
      { text: 'Overview', link: '/cve/overview' },
      { text: 'Synchronisation', link: '/cve/sync' },
      { text: 'Matching', link: '/cve/matching' },
      { text: 'Risk Scoring', link: '/cve/risk-scoring' },
    ],
  },
  {
    text: 'Dashboard',
    link: '/dashboard/',
  },
  {
    text: 'Administration',
    collapsed: false,
    items: [
      { text: 'Users', link: '/admin/users' },
      { text: 'Audit Log', link: '/admin/audit' },
      { text: 'Data Retention', link: '/admin/retention' },
    ],
  },
  {
    text: 'API Reference',
    collapsed: false,
    items: [
      { text: 'Overview', link: '/api/overview' },
      { text: 'Authentication', link: '/api/authentication' },
      { text: 'Endpoints', link: '/api/endpoints' },
      { text: 'WebSocket', link: '/api/websocket' },
      { text: 'Metrics', link: '/api/metrics' },
    ],
  },
  {
    text: 'Deployment',
    collapsed: false,
    items: [
      { text: 'Docker Compose', link: '/deployment/docker-compose' },
      { text: 'Environment Reference', link: '/deployment/env-reference' },
      { text: 'Secrets', link: '/deployment/secrets' },
      { text: 'Reverse Proxy', link: '/deployment/reverse-proxy' },
      { text: 'GeoIP', link: '/deployment/geoip' },
      { text: 'CVE Catalog Seed', link: '/deployment/cve-catalog-seed' },
      { text: 'Backup & Restore', link: '/deployment/backup-restore' },
      { text: 'Upgrade', link: '/deployment/upgrade' },
      { text: 'Offline Install', link: '/deployment/offline-install' },
      { text: 'Observability', link: '/deployment/observability' },
    ],
  },
  {
    text: 'Security',
    collapsed: false,
    items: [
      { text: 'Production Checklist', link: '/security/checklist' },
      { text: 'Responsible Scanning', link: '/security/responsible-scanning' },
    ],
  },
  {
    text: 'Troubleshooting',
    link: '/troubleshooting',
  },
];

export default defineConfig({
  title: 'UltraViolet',
  description: 'Self-hosted infrastructure scanner — user and operator documentation',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,

  head: [
    ['meta', { name: 'theme-color', content: '#7c3aed' }],
    ['meta', { property: 'og:title', content: 'UltraViolet Documentation' }],
    ['meta', { property: 'og:description', content: 'Self-hosted infrastructure scanner — user and operator documentation' }],
    ['meta', { property: 'og:type', content: 'website' }],
  ],

  themeConfig: {
    siteTitle: 'UltraViolet Docs',

    nav: [
      { text: 'Guide', link: '/getting-started/overview' },
      { text: 'API', link: '/api/overview' },
      { text: 'Deployment', link: '/deployment/docker-compose' },
    ],

    sidebar,

    outline: {
      level: [2, 3],
      label: 'On this page',
    },

    search: {
      provider: 'local',
    },

    footer: {
      message: 'UltraViolet Documentation',
      copyright: 'Self-hosted infrastructure scanner',
    },

    docFooter: {
      prev: 'Previous',
      next: 'Next',
    },
  },
});
