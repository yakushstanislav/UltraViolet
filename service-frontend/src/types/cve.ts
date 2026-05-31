export type CVE = {
  id: string;
  source?: string;
  summary?: string;
  cvss_score?: number;
  cvss_severity?: string;
  cvss_vector?: string;
  references?: string[];
  published_at?: string;
  last_modified_at?: string;
};

export type CVESyncStatusResponse = {
  bootstrapped: boolean;
  progress?: number;
  entries_done?: number;
  entries_total?: number;
};

export type ServiceCVE = {
  id: string;
  severity?: string;
  cvss_score?: number;
  summary?: string;
  matched_version?: string;
  matched_at: string;
};

export type ServiceCVESummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};
