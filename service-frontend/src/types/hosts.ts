import type { ServiceCVE, ServiceCVESummary } from './cve';

export type HostHTTPSecurityHeaders = {
  hsts?: string;
  csp?: string;
  x_frame_options?: string;
  x_content_type_options?: string;
};

export type HostHTTPSecurityInfo = {
  hsts_max_age?: number;
  hsts_include_subdomains?: boolean;
  hsts_preload?: boolean;
  csp_present?: boolean;
  csp_has_unsafe_inline?: boolean;
  csp_has_unsafe_eval?: boolean;
  x_frame_options?: string;
  x_content_type_options?: string;
  referrer_policy?: string;
  permissions_policy_present?: boolean;
  cors_allow_origin?: string;
  cookie_secure_count?: number;
  cookie_httponly_count?: number;
  cookie_samesite_strict_count?: number;
  cookie_samesite_lax_count?: number;
  cookie_samesite_none_count?: number;
};

export type HostHTTPRedirectStep = {
  url: string;
  status_code: number;
  location?: string;
};

export type HostHTTPResponse = {
  status_code?: number;
  server?: string;
  title?: string;
  headers?: Record<string, string>;
  body?: string;
  security_headers?: HostHTTPSecurityHeaders;
  security_info?: HostHTTPSecurityInfo;
  redirect_url?: string;
  favicon_hash?: number;
  technologies?: string[];
  redirect_chain?: HostHTTPRedirectStep[];
  robots_txt?: string;
  security_txt?: string;
  body_sha256?: string;
  not_found_hash?: string;
  alt_svc?: string;
  http3_supported?: boolean;
  has_screenshot?: boolean;
  captured_at: string;
};

export type HostTLSChainEntry = {
  position: number;
  subject?: string;
  issuer?: string;
  fingerprint_sha256?: string;
  not_before?: string;
  not_after?: string;
  sans?: string[];
};

export type HostTLSFindingSeverity =
  | 'info'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

export type HostTLSFinding = {
  severity: HostTLSFindingSeverity | string;
  code: string;
  detail?: string;
};

export type HostTLSCert = {
  subject?: string;
  issuer?: string;
  fingerprint_sha256?: string;
  not_before?: string;
  not_after?: string;
  days_until_expiry?: number;
  sans?: string[];
  jarm_fingerprint?: string;
  tls_version?: string;
  cipher_suite?: string;
  ja3s_hash?: string;
  ja4s_hash?: string;
  security_grade?: string;
  findings?: HostTLSFinding[];
  chain?: HostTLSChainEntry[];
};

export type HostSMTPInfo = {
  banner?: string;
  capabilities?: string[];
  starttls: boolean;
  auth_methods?: string[];
  max_message_size?: number;
};

export type HostServiceFingerprint = {
  product: string;
  version?: string;
  edition?: string;
  source?: string;
  role?: string;
  cluster_role?: string;
  cluster_name?: string;
  auth_required?: boolean;
  tls_required?: boolean;
  anonymous: boolean;
  captured_at: string;
};

export type HostSSHInfo = {
  server_version?: string;
  host_key_type?: string;
  host_key_fingerprint?: string;
  kex_algorithms?: string[];
  host_key_algorithms?: string[];
};

export type DnsRecord = {
  type: string;
  name: string;
  value: string;
  source: string;
  forward_confirmed: boolean;
  captured_at: string;
};

export type HostService = {
  id: number;
  port: number;
  transport: string;
  protocol?: string;
  banner?: string;
  banner_hash?: string;
  last_seen: string;
  risk_score: number;
  risk_factors?: string[];
  http?: HostHTTPResponse;
  tls?: HostTLSCert;
  ssh?: HostSSHInfo;
  smtp?: HostSMTPInfo;
  fingerprint?: HostServiceFingerprint;
  fingerprints?: HostServiceFingerprint[];
  cves?: ServiceCVE[];
  cve_summary?: ServiceCVESummary;
};

export type Host = {
  id: number;
  ip: string;
  country_code?: string;
  country_name?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: number;
  asn_org?: string;
  ptr_hostname?: string;
  first_seen: string;
  last_seen: string;
  risk_score?: number;
  risk_factors?: Array<{ code: string; label: string; weight: number }>;
  risk_updated_at?: string;
  page: number;
  limit: number;
  total: number;
  dns?: DnsRecord[];
  services?: HostService[];
};

export type RelatedHost = {
  ip: string;
  reason: 'cert_fingerprint' | 'jarm' | 'favicon_hash' | string;
  value: string;
  country_code?: string;
};

export type RelatedHostsResponse = {
  items: RelatedHost[];
  page: number;
  limit: number;
  total: number;
};

export type RTSPSnapshotRequest = {
  port: number;
  path: string;
  transport?: 'tcp' | 'udp';
  /** Server tries typical vendor paths after `path` (deduped, bounded). */
  auto_try_common_paths?: boolean;
  user?: string;
  password?: string;
};

export type RTSPSnapshotResponse = {
  blob: Blob;
  /** Present when auto path scan succeeded (see `X-UV-RTSP-Snapshot-Path`). */
  resolvedPath?: string;
};

export type ONVIFAuthMode = 'none' | 'basic' | 'digest' | 'wsse';

export type ONVIFCommand =
  | 'get_system_date_and_time'
  | 'get_capabilities'
  | 'get_device_information'
  | 'get_hostname'
  | 'get_media_profiles'
  | 'get_stream_uri'
  | 'get_video_sources'
  | 'get_snapshot_uri'
  | 'get_media_service_capabilities'
  | 'get_imaging_settings'
  | 'get_imaging_options'
  | 'get_ptz_configurations'
  | 'get_ptz_nodes'
  | 'get_ptz_status';

export type ONVIFCommandRequest = {
  port: number;
  scheme: 'http' | 'https';
  transport?: 'tcp';
  device_path?: string;
  /** Used for media presets (default /onvif/media_service on API). */
  media_service_path?: string;
  imaging_service_path?: string;
  ptz_service_path?: string;
  command: ONVIFCommand;
  profile_token?: string;
  video_source_token?: string;
  auth_mode?: ONVIFAuthMode;
  /** Legacy alias: prefer `response_shape: 'json'`. */
  parse?: boolean;
  response_shape?: 'raw' | 'json';
  user?: string;
  password?: string;
};

export type ONVIFCommandResponse = {
  status_code: number;
  content_type: string;
  body: string;
  truncated: boolean;
  // Parsed JSON form; structure depends on `command`.
  parsed?: Record<string, unknown>;
  parse_warnings?: string[];
};

export type ONVIFLabCredentialProbeRequest = {
  port: number;
  scheme: 'http' | 'https';
  transport?: 'tcp';
  device_path?: string;
  user?: string;
};

export type ONVIFLabCredentialProbeResponse =
  | {
      matched: true;
      username: string;
      password: string;
      attempts: number;
      http_code: number;
    }
  | {
      matched: false;
      attempts: number;
    };

export type ONVIFRTSPSnapshotRequest = {
  onvif_port: number;
  scheme: 'http' | 'https';
  media_service_path?: string;
  profile_token: string;
  transport?: 'tcp' | 'udp';
  auth_mode?: ONVIFAuthMode;
  user?: string;
  password?: string;
};
