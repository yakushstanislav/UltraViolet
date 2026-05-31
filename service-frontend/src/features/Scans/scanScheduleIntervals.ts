import type { TFunction } from 'i18next';

export const SCAN_SCHEDULE_INTERVAL_OPTIONS = [
  { seconds: 300, labelKey: 'scanSchedules.interval5m' },
  { seconds: 900, labelKey: 'scanSchedules.interval15m' },
  { seconds: 3600, labelKey: 'scanSchedules.interval1h' },
  { seconds: 21600, labelKey: 'scanSchedules.interval6h' },
  { seconds: 86400, labelKey: 'scanSchedules.interval24h' },
] as const;

export const SCAN_SCHEDULE_INTERVAL_SECONDS = SCAN_SCHEDULE_INTERVAL_OPTIONS.map(
  (opt) => opt.seconds
);

export function formatScanScheduleInterval(seconds: number, t: TFunction): string {
  const match = SCAN_SCHEDULE_INTERVAL_OPTIONS.find(
    (opt) => opt.seconds === seconds
  );

  if (match) {
    return t(match.labelKey);
  }

  if (seconds >= 3600 && seconds % 3600 === 0) {
    return t('scanSchedules.intervalHours', { count: seconds / 3600 });
  }

  if (seconds >= 60 && seconds % 60 === 0) {
    return t('scanSchedules.intervalMinutes', { count: seconds / 60 });
  }

  return t('scanSchedules.intervalMinutes', { count: Math.round(seconds / 60) });
}
