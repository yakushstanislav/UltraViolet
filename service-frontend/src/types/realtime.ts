export type RealtimeEventType =
  | 'scan.status'
  | 'scan.stats'
  | 'scan.snapshot'
  | 'scan.delta'
  | 'alert.fired';

export type RealtimeEvent = {
  type: RealtimeEventType | string;
  ts: string;
  scan_id?: number;
  data: unknown;
};

export type ScanStatusEventData = {
  status: string;
  started_at?: string;
  finished_at?: string;
  error?: string;
  cancel_requested?: boolean;
  pause_requested?: boolean;
};

export type ScanStatsEventData = {
  stats?: Record<string, unknown>;
  hosts_scanned?: number;
  progress?: number | null;
};

export type ScanSnapshotEventData = {
  host_id?: number;
  ip?: string;
  recent_hosts?: { host_id: number; ip: string }[];
};

export type AlertFiredEventData = {
  alert_rule_id: number;
  name: string;
  hits_count: number;
};
