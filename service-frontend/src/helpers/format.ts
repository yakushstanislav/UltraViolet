import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';

import i18n from '@i18n/i18n';

import type { PortExprItem } from '@/types/api';

dayjs.extend(relativeTime);

export function formatDate(value?: string): string {
  if (!value) {
    return '';
  }

  return dayjs(value).format('YYYY-MM-DD HH:mm:ss');
}

export function formatRelative(value?: string): string {
  if (!value) {
    return '';
  }

  const target = dayjs(value);
  const diffSeconds = dayjs().diff(target, 'second');

  if (diffSeconds <= 0) {
    return target.format('MMM D, YYYY');
  }

  if (diffSeconds < 60) {
    return `${diffSeconds}s ago`;
  }

  if (diffSeconds < 60 * 60) {
    return `${Math.floor(diffSeconds / 60)}m ago`;
  }

  if (diffSeconds < 60 * 60 * 24) {
    return `${Math.floor(diffSeconds / 3600)}h ago`;
  }

  if (diffSeconds < 60 * 60 * 24 * 7) {
    return `${Math.floor(diffSeconds / 86400)}d ago`;
  }

  return target.format('MMM D, YYYY');
}

/** Renders API `ports_expr` exactly as stored (from–to ranges). */
export function formatPortsExpr(items: PortExprItem[]): string {
  if (items.length === 0) {
    return '';
  }

  return items
    .map(({ from, to }) => (from === to ? String(from) : `${from}-${to}`))
    .join(', ');
}

export function statusClass(status: string): string {
  return `status status-${status.toLowerCase()}`;
}

/** Human-readable port-discovery engine label. */
function formatEngine(mode: string | undefined, slowProfile?: string): string {
  if (mode === 'masscan') {
    return i18n.t('format.engineMasscan');
  }

  if (mode === 'zmap') {
    return i18n.t('format.engineZmap');
  }

  if (slowProfile === 'balanced' || slowProfile === 'aggressive') {
    return i18n.t('format.engineSlowTcpProfile', { profile: slowProfile });
  }

  return i18n.t('format.engineSlowTcp');
}

/** Human-readable scan mode including target strategy when relevant. */
export function formatScanMode(
  mode: string | undefined,
  targetStrategy?: string,
  slowProfile?: string
): string {
  const engine = formatEngine(mode, slowProfile);

  if (targetStrategy === 'random') {
    return `${engine}${i18n.t('format.scanModeSep')}${i18n.t('format.scanModeRandomSuffix')}`;
  }

  return engine;
}
