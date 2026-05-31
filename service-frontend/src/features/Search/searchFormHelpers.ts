import type { TFunction } from 'i18next';

export type SearchFieldKey =
  | 'q'
  | 'q_mode'
  | 'port'
  | 'port_from'
  | 'port_to'
  | 'country'
  | 'asn'
  | 'protocol'
  | 'tls_issuer'
  | 'tls_fingerprint'
  | 'tls_subject'
  | 'tls_san'
  | 'ssh'
  | 'ssh_fingerprint'
  | 'smtp'
  | 'dns'
  | 'risk_score_min'
  | 'risk_score_max'
  | 'last_seen_from'
  | 'last_seen_to'
  | 'cve_severity'
  | 'cve_id'
  | 'cve_text'
  | 'confidence_gte';

export const SEARCH_FIELD_KEYS: SearchFieldKey[] = [
  'q',
  'q_mode',
  'port',
  'port_from',
  'port_to',
  'country',
  'asn',
  'protocol',
  'tls_issuer',
  'tls_fingerprint',
  'tls_subject',
  'tls_san',
  'ssh',
  'ssh_fingerprint',
  'smtp',
  'dns',
  'risk_score_min',
  'risk_score_max',
  'last_seen_from',
  'last_seen_to',
  'cve_severity',
  'cve_id',
  'cve_text',
  'confidence_gte',
];

export const Q_MODE_FUZZY = 'fuzzy' as const;

export type SearchQMode = 'auto' | typeof Q_MODE_FUZZY | 'exact';

const SEARCH_Q_MODES = new Set<string>(['auto', Q_MODE_FUZZY, 'exact']);

export function searchFieldTranslationKey(key: SearchFieldKey): string {
  return `search.fields.${key}`;
}

export function searchFieldPlaceholderKey(key: SearchFieldKey): string {
  return `search.fields.${key}_ph`;
}

export function optionalSearchParam(
  value: string
): string | undefined {
  return value !== '' ? value : undefined;
}

export function parseSearchQMode(value: string): SearchQMode | undefined {
  if (!SEARCH_Q_MODES.has(value)) {
    return undefined;
  }

  return value as SearchQMode;
}

export function formatSearchChipValue(
  key: SearchFieldKey,
  value: string,
  translate: TFunction
): string {
  if (key === 'q_mode' && value === Q_MODE_FUZZY) {
    return translate(searchFieldTranslationKey('q_mode'));
  }

  return value;
}

export const CVE_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

const PROMOTABLE_KEYS = new Set<SearchFieldKey>([
  'port',
  'port_from',
  'port_to',
  'country',
  'asn',
  'protocol',
  'tls_issuer',
  'tls_fingerprint',
  'tls_subject',
  'tls_san',
  'ssh',
  'ssh_fingerprint',
  'smtp',
  'dns',
  'cve_id',
  'cve_text',
  'cve_severity',
]);

export type SearchPromote = {
  key: SearchFieldKey;
  value: string;
};

export function parseSearchPromote(input: string): SearchPromote | null {
  const trimmed = input.trim();
  const colonIdx = trimmed.indexOf(':');
  if (colonIdx <= 0 || colonIdx >= trimmed.length - 1) {
    return null;
  }

  const rawKey = trimmed.slice(0, colonIdx).toLowerCase();
  const rawValue = trimmed.slice(colonIdx + 1).trim();
  if (rawValue === '') {
    return null;
  }

  const key = SEARCH_FIELD_KEYS.find((candidate) => candidate === rawKey);
  if (!key || !PROMOTABLE_KEYS.has(key)) {
    return null;
  }

  return { key, value: rawValue };
}

export const ADVANCED_FILTER_KEYS = [
  'protocol',
  'tls_issuer',
  'tls_fingerprint',
  'tls_subject',
  'tls_san',
  'ssh',
  'ssh_fingerprint',
  'smtp',
  'dns',
  'risk_score_min',
  'risk_score_max',
  'port_from',
  'port_to',
  'last_seen_from',
  'last_seen_to',
  'cve_severity',
  'cve_id',
  'cve_text',
  'confidence_gte',
] as const;

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export function dateInputToRFC3339(value: string, endOfDay: boolean): string {
  if (!value || !ISO_DATE_RE.test(value)) {
    return '';
  }

  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }

  const time = endOfDay ? 'T23:59:59Z' : 'T00:00:00Z';

  return `${value}${time}`;
}

export function rfc3339ToDateInput(value: string): string {
  if (!value || value.length < 10) {
    return '';
  }

  return value.slice(0, 10);
}
