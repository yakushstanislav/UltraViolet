import type { TFunction } from 'i18next';

import { isIPv4, parseCIDR } from './inetAddr';

/**
 * Returns a short hint when Masscan/Zmap is selected but the target is unlikely
 * to satisfy the API rule that every resolved CIDR must be IPv4.
 */
export function getSynEngineIPv4TargetHint(
  mode: 'slow' | 'masscan' | 'zmap',
  targetStrategy: 'sequential' | 'random' | 'country',
  target: string,
  t: TFunction
): string | null {
  if (mode === 'slow' || targetStrategy !== 'sequential') {
    return null;
  }

  const trimmed = target.trim();
  if (trimmed === '') {
    return null;
  }

  if (trimmed.includes(':')) {
    return t('scans.targetHints.synIpv6');
  }

  if (isIPv4(trimmed)) {
    return null;
  }

  const cidr = parseCIDR(trimmed);
  if (cidr && cidr.family === 'v4') {
    return null;
  }

  return t('scans.targetHints.synHostname');
}
