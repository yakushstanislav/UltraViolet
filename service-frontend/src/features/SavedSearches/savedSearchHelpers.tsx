import {
  Bug,
  Clock,
  Gauge,
  Globe,
  Hash,
  Layers,
  Lock,
  Mail,
  MapPin,
  Network,
  Search as SearchIcon,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import type { ReactNode } from 'react';
import type { TFunction } from 'i18next';

import { formatDate } from '@helpers/format';
import type { SearchQuery } from '@/types/common';

export const CVE_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

export const MAX_VISIBLE_CHIPS = 3;

export const SEVERITY_CHIP_CLASS: Record<string, string> = {
  CRITICAL: 'severity-chip severity-chip-critical',
  HIGH: 'severity-chip severity-chip-high',
  MEDIUM: 'severity-chip severity-chip-medium',
  LOW: 'severity-chip severity-chip-low',
};

export type ChipCategory = 'q' | 'net' | 'cve' | 'tls' | 'time';

export type ChipVisual = {
  category: ChipCategory;
  icon: ReactNode;
};

const QUERY_KEY_META: Record<string, ChipVisual> = {
  q: { category: 'q', icon: <SearchIcon aria-hidden size={11} /> },
  port: { category: 'net', icon: <Network aria-hidden size={11} /> },
  country: { category: 'net', icon: <MapPin aria-hidden size={11} /> },
  protocol: { category: 'net', icon: <Layers aria-hidden size={11} /> },
  asn: { category: 'net', icon: <Hash aria-hidden size={11} /> },
  has_cve: { category: 'cve', icon: <Bug aria-hidden size={11} /> },
  cve_severity: {
    category: 'cve',
    icon: <ShieldAlert aria-hidden size={11} />,
  },
  risk_score_min: { category: 'cve', icon: <Gauge aria-hidden size={11} /> },
  risk_score_max: { category: 'cve', icon: <Gauge aria-hidden size={11} /> },
  tls_issuer: { category: 'tls', icon: <Lock aria-hidden size={11} /> },
  tls_fingerprint: { category: 'tls', icon: <Lock aria-hidden size={11} /> },
  tls_subject: { category: 'tls', icon: <Lock aria-hidden size={11} /> },
  tls_san: { category: 'tls', icon: <Lock aria-hidden size={11} /> },
  ssh: { category: 'net', icon: <Terminal aria-hidden size={11} /> },
  ssh_fingerprint: { category: 'net', icon: <Terminal aria-hidden size={11} /> },
  smtp: { category: 'net', icon: <Mail aria-hidden size={11} /> },
  dns: { category: 'net', icon: <Globe aria-hidden size={11} /> },
  cve_id: { category: 'cve', icon: <Bug aria-hidden size={11} /> },
  cve_text: { category: 'cve', icon: <Bug aria-hidden size={11} /> },
  q_mode: { category: 'q', icon: <SearchIcon aria-hidden size={11} /> },
  last_seen_from: { category: 'time', icon: <Clock aria-hidden size={11} /> },
  last_seen_to: { category: 'time', icon: <Clock aria-hidden size={11} /> },
};

export function chipLabel(key: string, translate: TFunction): string {
  const tk = `savedSearches.chip.${key}`;
  const out = translate(tk);

  return out !== tk ? out : key;
}

export function getChipVisual(key: string): ChipVisual {
  return (
    QUERY_KEY_META[key] ?? {
      category: 'q',
      icon: <SearchIcon aria-hidden size={11} />,
    }
  );
}

export function formatChipValue(key: string, value: unknown): string {
  if (key === 'last_seen_from' || key === 'last_seen_to') {
    const parsed = new Date(String(value));

    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString().slice(0, 10);
    }
  }

  return String(value);
}

export function dateInputToRFC3339(value: string, endOfDay: boolean): string {
  if (!value) {
    return '';
  }

  const time = endOfDay ? 'T23:59:59Z' : 'T00:00:00Z';

  return `${value}${time}`;
}

export function renderQueryChip(
  key: string,
  value: unknown,
  translate: TFunction
) {
  const meta = getChipVisual(key);

  const severityKey =
    key === 'cve_severity' && typeof value === 'string'
      ? value.toUpperCase()
      : '';

  const valueNode = SEVERITY_CHIP_CLASS[severityKey] ? (
    <span className={SEVERITY_CHIP_CLASS[severityKey]}>{String(value)}</span>
  ) : (
    <span className="query-tag-val">{formatChipValue(key, value)}</span>
  );

  return (
    <span
      className={`query-tag query-tag--${meta.category}`}
      key={key}
      title={`${key}: ${String(value)}`}
    >
      <span className="query-tag-icon">{meta.icon}</span>
      <span className="query-tag-key">{chipLabel(key, translate)}</span>
      <span className="query-tag-sep">:</span>
      {valueNode}
    </span>
  );
}

export function renderQueryTags(
  query: SearchQuery | null | undefined,
  translate: TFunction
) {
  const entries = Object.entries(query ?? {}).filter(
    ([, v]) => v !== '' && v !== null && v !== undefined
  );

  if (entries.length === 0) {
    return <span className="query-tags-empty">{translate('common.dash')}</span>;
  }

  const visible = entries.slice(0, MAX_VISIBLE_CHIPS);
  const overflow = entries.slice(MAX_VISIBLE_CHIPS);

  return (
    <div className="query-tags">
      {visible.map(([k, v]) => renderQueryChip(k, v, translate))}
      {overflow.length > 0 && (
        <span
          className="query-tag query-tag--more"
          title={overflow.map(([k, v]) => `${k}: ${String(v)}`).join('\n')}
        >
          {translate('savedSearches.moreOverflow', { count: overflow.length })}
        </span>
      )}
    </div>
  );
}

export type LastRunVariant = 'never' | 'fresh' | 'neutral' | 'stale';

export function lastRunInfo(
  lastRunAt: string | undefined,
  translate: TFunction
): { label: string; variant: LastRunVariant } {
  if (!lastRunAt) {
    return { label: translate('savedSearches.neverRan'), variant: 'never' };
  }

  const parsed = new Date(lastRunAt).getTime();

  if (Number.isNaN(parsed)) {
    return { label: translate('savedSearches.neverRan'), variant: 'never' };
  }

  const days = (Date.now() - parsed) / (24 * 3600 * 1000);
  const label = formatDate(lastRunAt);

  if (days < 7) {
    return { label, variant: 'fresh' };
  }

  if (days < 30) {
    return { label, variant: 'neutral' };
  }

  return { label, variant: 'stale' };
}

export function renderLastRun(
  lastRunAt: string | undefined,
  translate: TFunction
) {
  const { label, variant } = lastRunInfo(lastRunAt, translate);

  return (
    <span className={`last-run-pill last-run-pill-${variant}`}>{label}</span>
  );
}

export type SavedSearchFormValues = {
  q: string;
  port: string;
  country: string;
  protocol: string;
  asn: string;
  hasCve: string;
  cveSeverity: string;
  tlsIssuer: string;
  tlsFingerprint: string;
  riskMin: string;
  riskMax: string;
  lastSeenFrom: string;
  lastSeenTo: string;
};

export function buildSavedSearchQuery(
  values: SavedSearchFormValues
): SearchQuery {
  const query: SearchQuery = {};

  if (values.q) query.q = values.q;
  if (values.port) query.port = values.port;
  if (values.country) query.country = values.country;
  if (values.protocol) query.protocol = values.protocol;
  if (values.asn) query.asn = values.asn;
  if (values.cveSeverity) query.cve_severity = values.cveSeverity;
  if (values.tlsIssuer) query.tls_issuer = values.tlsIssuer;
  if (values.tlsFingerprint) query.tls_fingerprint = values.tlsFingerprint;
  if (values.riskMin) query.risk_score_min = values.riskMin;
  if (values.riskMax) query.risk_score_max = values.riskMax;
  if (values.lastSeenFrom)
    query.last_seen_from = dateInputToRFC3339(values.lastSeenFrom, false);
  if (values.lastSeenTo)
    query.last_seen_to = dateInputToRFC3339(values.lastSeenTo, true);
  if (values.hasCve) query.has_cve = values.hasCve;

  return query;
}
