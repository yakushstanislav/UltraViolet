import type { TFunction } from 'i18next';

export type CVESeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

const SEVERITY_LABEL_KEY: Record<CVESeverity, string> = {
  CRITICAL: 'searchPage.sevCritical',
  HIGH: 'searchPage.sevHigh',
  MEDIUM: 'searchPage.sevMedium',
  LOW: 'searchPage.sevLow',
};

const SEVERITY_CLASS: Record<CVESeverity, string> = {
  CRITICAL: 'cve-severity cve-severity-critical',
  HIGH: 'cve-severity cve-severity-high',
  MEDIUM: 'cve-severity cve-severity-medium',
  LOW: 'cve-severity cve-severity-low',
};

function toCVESeverity(value: string | undefined): CVESeverity | null {
  switch ((value ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MEDIUM':
      return 'MEDIUM';
    case 'LOW':
      return 'LOW';
    default:
      return null;
  }
}

export function cveSeverityLabel(
  severity: string | undefined,
  t: TFunction
): string {
  const key = toCVESeverity(severity);
  if (key === null) {
    return severity ?? '';
  }

  return t(SEVERITY_LABEL_KEY[key]);
}

export function cveSeverityClass(severity: string | undefined): string {
  const key = toCVESeverity(severity);
  if (key === null) {
    return 'cve-severity cve-severity-unknown';
  }

  return SEVERITY_CLASS[key];
}
