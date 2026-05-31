import type { TFunction } from 'i18next';

import { isIPv4 } from './inetAddr';

/**
 * Returns a validation message for obviously invalid IPv4 / CIDR forms,
 * or null when the target is syntactically acceptable (hostname and IPv6
 * are left to the API).
 */
export function describeScanTargetIssue(
  target: string,
  t: TFunction
): string | null {
  const trimmed = target.trim();
  if (trimmed === '') {
    return null;
  }

  if (
    trimmed.includes('.') &&
    trimmed.includes('/') &&
    !trimmed.includes(':')
  ) {
    const slash = trimmed.lastIndexOf('/');
    const host = trimmed.slice(0, slash);
    const maskStr = trimmed.slice(slash + 1);
    const prefix = Number(maskStr);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      return t('scans.targetHints.ipv4CidrPrefix');
    }

    if (!isIPv4(host)) {
      return t('scans.targetHints.invalidIpv4BeforeMask');
    }

    return null;
  }

  if (/^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) {
    if (!isIPv4(trimmed)) {
      return t('scans.targetHints.invalidIpv4');
    }

    return null;
  }

  if (trimmed.includes(':') && trimmed.includes('/')) {
    const slash = trimmed.lastIndexOf('/');
    const maskStr = trimmed.slice(slash + 1);
    const prefix = Number(maskStr);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
      return t('scans.targetHints.ipv6CidrPrefix');
    }

    return null;
  }

  if (trimmed.length > 253) {
    return t('scans.targetHints.hostnameTooLong');
  }

  if (!/^[a-zA-Z0-9.-]+$/.test(trimmed)) {
    return t('scans.targetHints.hostnameChars');
  }

  return null;
}
