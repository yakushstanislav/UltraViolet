export type PortExprItem = {
  from: number;
  to: number;
};

export type ScanStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'DONE'
  | 'FAILED'
  | 'CANCELED'
  | 'PAUSED';

export type ScanTargetStrategy = 'sequential' | 'random' | 'country';

export type SlowProfile = 'stealth' | 'balanced' | 'aggressive';

export type ScanMode = 'slow' | 'masscan' | 'zmap';

export type RecentScannedHost = {
  host_id: number;
  ip: string;
  scanned_at: string;
};

export type Scan = {
  id: number;
  name?: string;
  cidr?: string;
  country?: string;
  ports_expr: PortExprItem[];
  mode?: ScanMode;
  slow_profile?: SlowProfile;
  target_strategy?: ScanTargetStrategy;
  host_limit?: number;
  status: ScanStatus;
  started_at?: string;
  finished_at?: string;
  error?: string;
  // Backend-agnostic telemetry payload; shape varies by mode.
  stats?: Record<string, unknown>;
  stats_updated_at?: string;
  created_at: string;
  cancel_requested?: boolean;
  pause_requested?: boolean;
  hosts_scanned?: number;
  progress?: number | null;
  recent_hosts?: RecentScannedHost[];
  schedule_id?: number;
};

export type ScanDeltaSummary = {
  scan_id: number;
  previous_scan_id: number | null;
  new_services: number;
  disappeared_services: number;
  changed_services: number;
  created_at: string;
};

export type CancelScanResponse = {
  id: number;
  status: ScanStatus;
};

export type PauseScanResponse = {
  id: number;
  status: ScanStatus;
};

export type ResumeScanResponse = {
  id: number;
  status: ScanStatus;
};

export type RestartScanResponse = {
  id: number;
  status: ScanStatus;
};

export type ScanListResponse = {
  page: number;
  limit: number;
  total: number;
  scans: Scan[];
};

export type CreateScanRequest = {
  name?: string;
  target?: string;
  scan_subnet?: boolean;
  mode?: ScanMode;
  slow_profile?: SlowProfile;
  target_strategy?: ScanTargetStrategy;
  country?: string;
  limit?: number;
  ports_expr: PortExprItem[];
};

export type CreateScanResponse = {
  scan_ids: number[];
  queued: number;
};

export type ScanDeltaEvent = {
  id: number;
  ScanID?: number;
  HostID?: number;
  ServiceID?: { Valid: boolean; Int64: number } | null;
  ChangeType: 'new' | 'disappeared' | 'changed' | string;
  // Backend-agnostic event payload; shape varies by ChangeType.
  Details?: Record<string, unknown> | null;
  CreatedAt: string;
};

export type ScanDeltaEventsResponse = {
  page: number;
  limit: number;
  total: number;
  items: ScanDeltaEvent[];
};
