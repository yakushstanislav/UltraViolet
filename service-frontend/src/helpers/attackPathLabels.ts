import type { TFunction } from 'i18next';

const FALLBACK_PREFIX = 'shared';

function toKey(type: string): string {
  if (type === '') {
    return FALLBACK_PREFIX;
  }

  return type.replace(/[^a-z0-9_]/gi, '_').toLowerCase();
}

export function relationTypeLabel(type: string, t: TFunction): string {
  return t(`risk.attackPath.relation.${toKey(type)}`, {
    defaultValue: type,
  });
}
