import type { PivotNode, PivotResponse } from '@/types/pivot';

import { hostIPLiteral } from '@helpers/hostPathFromScanTarget';

export type PivotGraphTheme = {
  artifact: string;
  background: string;
  host: string;
  label: string;
  link: string;
  service: string;
};

export function pivotGraphTheme(theme: 'light' | 'dark'): PivotGraphTheme {
  if (theme === 'dark') {
    return {
      background: '#070b1a',
      link: 'rgba(148, 163, 184, 0.35)',
      label: '#cbd5e1',
      host: '#60a5fa',
      service: '#6474a8',
      artifact: '#22d3ee',
    };
  }

  return {
    background: '#eef2f7',
    link: 'rgba(100, 116, 139, 0.45)',
    label: '#334155',
    host: '#2563eb',
    service: '#64748b',
    artifact: '#0891b2',
  };
}

export function pivotStats(data: PivotResponse): {
  hostCount: number;
  serviceCount: number;
} {
  let hostCount = 0;
  let serviceCount = 0;

  for (const node of data.nodes) {
    if (node.kind === 'host') {
      hostCount += 1;
    }

    if (node.kind === 'service') {
      serviceCount += 1;
    }
  }

  return { hostCount, serviceCount };
}

export function pivotSearchParams(kind: string, value: string): URLSearchParams {
  const params = new URLSearchParams();

  switch (kind) {
    case 'tls_fingerprint':
      params.set('tls_fingerprint', value);
      break;
    case 'jarm':
      params.set('jarm', value);
      break;
    case 'ja3s':
      params.set('ja3s', value);
      break;
    case 'ja4s':
      params.set('ja4s', value);
      break;
    case 'favicon_hash':
      params.set('favicon_hash', value);
      break;
    case 'body_sha256':
      params.set('body_sha256', value);
      break;
    case 'http_title':
      params.set('http_title', value);
      break;
    default:
      params.set('q', value);
  }

  return params;
}

export function pivotNodeLabel(node: PivotNode): string {
  if (node.kind === 'service' && node.ip !== undefined && node.port !== undefined) {
    const ip = hostIPLiteral(node.ip);

    if (ip) {
      return `${ip}:${String(node.port)}`;
    }
  }

  if (node.kind === 'host' && node.ip !== undefined) {
    const ip = hostIPLiteral(node.ip);

    if (ip) {
      return ip;
    }
  }

  return node.label ?? node.id;
}

export function nodeColor(node: PivotNode, palette: PivotGraphTheme): string {
  switch (node.kind) {
    case 'host':
      return palette.host;
    case 'artifact':
      return palette.artifact;
    default:
      return palette.service;
  }
}

export function nodeHaloColor(node: PivotNode): string | undefined {
  if (node.kind !== 'service' || node.risk_score === undefined) {
    return undefined;
  }

  if (node.risk_score >= 75) {
    return 'rgba(239, 68, 68, 0.45)';
  }

  if (node.risk_score >= 50) {
    return 'rgba(249, 115, 22, 0.4)';
  }

  return undefined;
}

export function pivotPath(kind: string, value: string): string {
  return `/pivot/${encodeURIComponent(kind)}/${encodeURIComponent(value)}`;
}
