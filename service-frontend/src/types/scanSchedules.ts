import type { PortExprItem, ScanMode, ScanTargetStrategy, SlowProfile } from '@/types/scans';

export type ScanSchedule = {
  id: number;
  name: string;
  enabled: boolean;
  interval_seconds: number;
  target?: string;
  scan_subnet: boolean;
  country?: string;
  mode: ScanMode;
  slow_profile: SlowProfile;
  target_strategy: ScanTargetStrategy;
  host_limit?: number;
  ports_expr: PortExprItem[];
  last_run_at?: string;
  last_scan_id?: number;
  next_run_at: string;
  created_at: string;
  updated_at: string;
};

export type ScanScheduleListResponse = {
  page: number;
  limit: number;
  total: number;
  schedules: ScanSchedule[];
};

export type CreateScanScheduleRequest = {
  name: string;
  interval_seconds: number;
  enabled?: boolean;
  target?: string;
  scan_subnet?: boolean;
  mode?: ScanMode;
  slow_profile?: SlowProfile;
  target_strategy?: ScanTargetStrategy;
  country?: string;
  limit?: number;
  ports_expr: PortExprItem[];
};

export type UpdateScanScheduleRequest = Partial<
  Omit<CreateScanScheduleRequest, 'ports_expr'>
> & {
  ports_expr?: PortExprItem[];
};
