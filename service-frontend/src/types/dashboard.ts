import type { ScanStatus } from './scans';

export type DashboardTopCVE = {
  id: string;
  severity?: string;
  cvss_score?: number;
  summary?: string;
  services: number;
};

export type DashboardStats = {
  hosts: number;
  services: number;
  pending: number;
  running: number;
  paused: number;
  done: number;
  failed: number;
  scans_24h: number;
  scans_7d: number;
  scans_30d: number;
  last_scan_finished_at?: string;
  alerts_active: number;
  alerts_fired_24h: number;
  saved_searches: number;
  change_events_7d_new: number;
  change_events_7d_disappeared: number;
  change_events_7d_changed: number;
  hosts_with_critical_cve?: number;
  cve_critical?: number;
  cve_high?: number;
  cve_medium?: number;
  cve_low?: number;
  top_cves?: DashboardTopCVE[];
};

export type DashboardMapCountryRow = {
  country_code: string;
  count: number;
};

export type DashboardMapPointRow = {
  latitude: number;
  longitude: number;
  country_code?: string;
};

export type DashboardMapPointsSource = 'geo' | 'country_centroid';

export type DashboardMapResponse = {
  countries: DashboardMapCountryRow[];
  points: DashboardMapPointRow[];
  points_source?: DashboardMapPointsSource;
};

export type DashboardGlobeViewMode = 'hosts' | 'countries';

export type DashboardTrendsRange = '24h' | '7d' | '30d';
export type DashboardTrendsBucket = 'hour' | 'day';

export type DashboardTrendsPoint = {
  ts: string;
  scans_created: number;
  scans_completed: number;
  hosts_discovered: number;
  change_new: number;
  change_disappeared: number;
  change_changed: number;
};

export type DashboardTrendsResponse = {
  range: DashboardTrendsRange;
  bucket: DashboardTrendsBucket;
  points: DashboardTrendsPoint[];
};

export type DashboardTopPortRow = {
  port: number;
  count: number;
};

export type DashboardTopProtocolRow = {
  protocol: string;
  count: number;
};

export type DashboardTopASNRow = {
  asn: number;
  asn_org?: string;
  count: number;
};

export type DashboardTopCountryRow = {
  country_code: string;
  count: number;
};

export type DashboardTopTLSIssuerRow = {
  issuer: string;
  count: number;
};

export type DashboardTopResponse = {
  limit: number;
  top_ports: DashboardTopPortRow[];
  top_protocols: DashboardTopProtocolRow[];
  top_asn: DashboardTopASNRow[];
  top_countries: DashboardTopCountryRow[];
  top_tls_issuers: DashboardTopTLSIssuerRow[];
};

export type DashboardRiskScoreBucket = {
  bucket: string;
  count: number;
};

export type DashboardRiskService = {
  service_id: number;
  host_ip: string;
  port: number;
  protocol?: string;
  risk_score: number;
  top_factor?: string;
};

export type DashboardRiskHost = {
  host_id: number;
  ip: string;
  country_code?: string;
  high_risk_services_count?: number;
  risk_score: number;
  top_factor?: string;
};

export type DashboardRiskResponse = {
  score_buckets: DashboardRiskScoreBucket[];
  host_score_buckets?: DashboardRiskScoreBucket[];
  top_risky_services: DashboardRiskService[];
  top_risky_hosts: DashboardRiskHost[];
};

export type DashboardRecentScan = {
  scan_id: number;
  name?: string;
  status: ScanStatus;
  duration_sec?: number;
  services_found: number;
  new_services: number;
  disappeared_services: number;
  changed_services: number;
  finished_at?: string;
};

export type DashboardScansSummaryResponse = {
  avg_duration_sec?: number;
  median_duration_sec?: number;
  success_rate_7d?: number;
  recent: DashboardRecentScan[];
};
