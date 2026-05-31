import type { ScanFormValues } from '@schemas/scan';

import type { CreateScanRequest } from '@/types/scans';
import type { CreateScanScheduleRequest } from '@/types/scanSchedules';

export function scanFormValuesToScanPayload(
  values: ScanFormValues
): CreateScanRequest {
  return {
    name: values.name,
    target:
      values.targetStrategy === 'sequential' ? values.target : undefined,
    scan_subnet:
      values.targetStrategy === 'sequential' ? values.scanSubnet : undefined,
    mode: values.mode,
    slow_profile: values.mode === 'slow' ? values.slowProfile : undefined,
    target_strategy: values.targetStrategy,
    country:
      values.targetStrategy === 'country'
        ? values.country?.toUpperCase()
        : undefined,
    limit:
      values.targetStrategy === 'random' || values.targetStrategy === 'country'
        ? values.hostLimit
        : undefined,
    ports_expr: values.portsExpr,
  };
}

export function scanFormValuesToScheduleRequest(
  values: ScanFormValues,
  intervalSeconds: number,
  fallbackName: string
): CreateScanScheduleRequest {
  const scanPayload = scanFormValuesToScanPayload(values);
  const { name: scanName, ...scheduleTemplate } = scanPayload;

  return {
    ...scheduleTemplate,
    name: scanName || values.target || fallbackName,
    interval_seconds: intervalSeconds,
  };
}
