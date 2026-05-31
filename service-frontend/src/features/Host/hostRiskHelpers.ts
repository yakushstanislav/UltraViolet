import type { HostService } from '@/types/api';

export const HIGH_RISK_PORTS = new Set([22, 3389, 5900, 2375, 6443]);

export const MEDIUM_RISK_PORTS = new Set([
  21, 23, 445, 3306, 5432, 6379, 27017,
]);

export const BODY_PREVIEW_CHARS = 700;

export function riskLabel(service: HostService): 'high' | 'medium' | 'low' {
  if (HIGH_RISK_PORTS.has(service.port)) {
    return 'high';
  }

  if (MEDIUM_RISK_PORTS.has(service.port)) {
    return 'medium';
  }

  return 'low';
}

export type RiskTier = 'critical' | 'high' | 'medium' | 'low';

export function riskTier(score: number): RiskTier {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';

  return 'low';
}

export function riskScoreClass(score: number): string {
  return `risk-${riskTier(score)}`;
}

export function tlsExpiryClass(days: number): string {
  if (days < 0) return 'tls-expired';
  if (days < 30) return 'tls-expiring';
  return '';
}

export function hasServiceDetails(service: HostService): boolean {
  return (
    Boolean(service.banner?.trim()) ||
    service.http !== undefined ||
    service.tls !== undefined ||
    service.ssh !== undefined ||
    service.smtp !== undefined ||
    service.fingerprint !== undefined ||
    (service.cves !== undefined && service.cves.length > 0)
  );
}

export function cveSeverityClass(severity?: string): string {
  switch ((severity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'cve-severity cve-severity-critical';
    case 'HIGH':
      return 'cve-severity cve-severity-high';
    case 'MEDIUM':
      return 'cve-severity cve-severity-medium';
    case 'LOW':
      return 'cve-severity cve-severity-low';
    default:
      return 'cve-severity cve-severity-unknown';
  }
}

export function cveCountTotal(service: HostService): number {
  if (service.cve_summary) {
    const summary = service.cve_summary;

    return summary.critical + summary.high + summary.medium + summary.low;
  }

  return service.cves?.length ?? 0;
}
