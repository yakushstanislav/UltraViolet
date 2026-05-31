import { copyTextToClipboard as copyTextToClipboardImpl } from '@helpers/clipboard';

import type { HostService } from '@/types/hosts';

export function hostServiceEligibleForOnvif(service: HostService): boolean {
  const p = (service.protocol ?? '').toLowerCase();

  return p === 'onvif' || service.fingerprint?.product === 'onvif';
}

export function defaultOnvifScheme(service: HostService): 'http' | 'https' {
  if (service.tls !== undefined) {
    return 'https';
  }

  if ((service.protocol ?? '').toLowerCase() === 'https') {
    return 'https';
  }

  return 'http';
}

export type HttpVisitTarget = {
  serviceId: number;
  port: number;
  scheme: 'http' | 'https';
  statusCode?: number;
  server?: string;
  title?: string;
};

function httpVisitTargetSortKey(target: HttpVisitTarget): number {
  if (target.port === 443 && target.scheme === 'https') {
    return 0;
  }
  if (target.port === 80 && target.scheme === 'http') {
    return 1;
  }

  return 100 + target.port;
}

export function collectHttpVisitTargets(
  services: HostService[]
): HttpVisitTarget[] {
  const targets = services
    .filter((service) => service.http !== undefined)
    .map((service) => ({
      serviceId: service.id,
      port: service.port,
      scheme: defaultOnvifScheme(service),
      statusCode: service.http?.status_code,
      server: service.http?.server,
      title: service.http?.title,
    }));

  return targets.sort(
    (left, right) => httpVisitTargetSortKey(left) - httpVisitTargetSortKey(right)
  );
}

export function defaultHttpVisitTargetId(
  targets: HttpVisitTarget[]
): number | undefined {
  return targets[0]?.serviceId;
}

function formatHostAuthority(ip: string, port: number): string {
  const host = ip.includes(':') ? `[${ip}]` : ip;

  return `${host}:${port}`;
}

export function buildHttpVisitUrl(ip: string, target: HttpVisitTarget): string {
  const defaultPort = target.scheme === 'https' ? 443 : 80;
  const authority =
    target.port === defaultPort
      ? ip.includes(':')
        ? `[${ip}]`
        : ip
      : formatHostAuthority(ip, target.port);

  return `${target.scheme}://${authority}/`;
}

const httpVisitOptionDetailMaxLen = 56;

function truncateHttpVisitDetail(
  value: string,
  maxLen = httpVisitOptionDetailMaxLen
): string {
  if (value.length <= maxLen) {
    return value;
  }

  return `${value.slice(0, maxLen - 1)}…`;
}

export function formatHttpVisitSelectLabel(target: HttpVisitTarget): string {
  const parts: string[] = [
    String(target.port),
    target.scheme.toUpperCase(),
  ];

  if (target.statusCode !== undefined) {
    parts.push(String(target.statusCode));
  }

  const detail = target.server ?? target.title;
  if (detail !== undefined && detail !== '') {
    parts.push(truncateHttpVisitDetail(detail, 40));
  }

  return parts.join(' · ');
}

export function formatHttpVisitOptionDetail(
  target: HttpVisitTarget
): string | undefined {
  const parts: string[] = [];

  if (target.statusCode !== undefined) {
    parts.push(String(target.statusCode));
  }

  const detail = target.server ?? target.title;
  if (detail !== undefined && detail !== '') {
    parts.push(truncateHttpVisitDetail(detail));
  }

  if (parts.length === 0) {
    return undefined;
  }

  return parts.join(' · ');
}

export type HttpStatusTone = 'ok' | 'redirect' | 'error' | 'unknown';

export function httpStatusTone(statusCode?: number): HttpStatusTone {
  if (statusCode === undefined) {
    return 'unknown';
  }

  if (statusCode >= 200 && statusCode < 300) {
    return 'ok';
  }

  if (statusCode >= 300 && statusCode < 400) {
    return 'redirect';
  }

  return 'error';
}

export function httpStatusToneClass(tone: HttpStatusTone): string {
  if (tone === 'ok') {
    return 'host-http-status-ok';
  }

  if (tone === 'redirect') {
    return 'host-http-status-redirect';
  }

  if (tone === 'error') {
    return 'host-http-status-error';
  }

  return 'host-http-status-unknown';
}

/** @deprecated Import from `@helpers/clipboard` — kept for existing call sites. */
export function copyTextToClipboard(
  payload: string,
  onSuccess: () => void,
  onError?: () => void
): void {
  copyTextToClipboardImpl(payload, onSuccess, onError);
}
