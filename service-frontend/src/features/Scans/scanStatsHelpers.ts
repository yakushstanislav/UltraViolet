import i18n from '@i18n/i18n';

export const SCAN_STAT_KEY_ORDER = [
  'hosts_scanned',
  'open_ports',
  'probed',
  'stored',
  'errors',
] as const;

export type BuildStatChipsOptions = {
  variant?: 'default' | 'table';
};

export type StatChipModel = {
  rawKey: string;
  label: string;
  valueText: string;
  tone: 'default' | 'danger';
};

export function statKeyOrderIndex(key: string): number {
  const idx = SCAN_STAT_KEY_ORDER.indexOf(
    key as (typeof SCAN_STAT_KEY_ORDER)[number]
  );

  return idx === -1 ? 999 : idx;
}

export function humanizeStatKey(
  key: string,
  variant: 'default' | 'table' = 'default'
): string {
  if (variant === 'table') {
    const shortKey = `scans.stats.${key}_short`;
    if (i18n.exists(shortKey)) {
      return i18n.t(shortKey);
    }
  }

  const labelKey = `scans.stats.${key}`;
  if (i18n.exists(labelKey)) {
    return i18n.t(labelKey);
  }

  return key.replace(/_/g, ' ');
}

function statChipLabel(key: string, variant: 'default' | 'table'): string {
  return humanizeStatKey(key, variant);
}

export function toNonNegativeCount(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
    return Math.floor(value);
  }

  if (typeof value === 'string' && value !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed) && parsed >= 0) {
      return Math.floor(parsed);
    }
  }

  return 0;
}

export function formatStatScalar(value: unknown): string {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return new Intl.NumberFormat('en-US').format(value);
  }

  if (typeof value === 'boolean') {
    return value ? i18n.t('common.yes') : i18n.t('common.no');
  }

  if (value === null || value === undefined) {
    return '';
  }

  if (typeof value === 'string' && value !== '' && /^\d+$/.test(value)) {
    return new Intl.NumberFormat('en-US').format(Number(value));
  }

  return String(value);
}

export function buildStatChips(
  stats?: Record<string, unknown>,
  options?: BuildStatChipsOptions
): StatChipModel[] {
  if (!stats) {
    return [];
  }

  const variant = options?.variant ?? 'default';

  const pairs = Object.entries(stats).filter(
    ([, value]) => value !== null && value !== undefined
  );

  pairs.sort(([a], [b]) => {
    const diff = statKeyOrderIndex(a) - statKeyOrderIndex(b);

    if (diff !== 0) {
      return diff;
    }

    return a.localeCompare(b);
  });

  return pairs.map(([key, value]) => ({
    rawKey: key,
    label: statChipLabel(key, variant),
    valueText: formatStatScalar(value),
    tone:
      key === 'errors' && toNonNegativeCount(value) > 0 ? 'danger' : 'default',
  }));
}

export function formatStats(stats?: Record<string, unknown>): string {
  const chips = buildStatChips(stats);
  if (chips.length === 0) {
    return i18n.t('common.na');
  }

  return chips.map((c) => `${c.label}: ${c.valueText}`).join(' · ');
}
