import { isCIDR, isIPv4, isIPv6 } from '@helpers/inetAddr';

export type FilterKey =
  | 'port'
  | 'country'
  | 'asn'
  | 'protocol'
  | 'tls_issuer'
  | 'tls_fingerprint';

export const FILTER_KEYS: FilterKey[] = [
  'port',
  'country',
  'asn',
  'protocol',
  'tls_issuer',
  'tls_fingerprint',
];

const FILTER_KEY_SET = new Set<string>(FILTER_KEYS);

export type ParsedQuery = {
  filters: Partial<Record<FilterKey, string>>;
  q: string;
  qKind: 'ip' | 'cidr' | 'text' | 'empty';
  raw: string;
};

type Token =
  | { kind: 'filter'; key: FilterKey; value: string }
  | { kind: 'word'; value: string };

function tokenize(input: string): string[] {
  const out: string[] = [];
  let buf = '';
  let inQuote = false;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];

    if (ch === '"') {
      inQuote = !inQuote;
      continue;
    }

    if (!inQuote && (ch === ' ' || ch === '\t')) {
      if (buf !== '') {
        out.push(buf);
        buf = '';
      }
      continue;
    }

    buf += ch;
  }

  if (buf !== '') {
    out.push(buf);
  }

  return out;
}

function classifyToken(
  raw: string
): Token | { kind: 'pending-key'; key: FilterKey } {
  const colon = raw.indexOf(':');
  if (colon > 0) {
    const key = raw.slice(0, colon).toLowerCase();
    const value = raw.slice(colon + 1);
    if (FILTER_KEY_SET.has(key)) {
      if (value === '') {
        return { kind: 'pending-key', key: key as FilterKey };
      }

      return { kind: 'filter', key: key as FilterKey, value };
    }
  }

  return { kind: 'word', value: raw };
}

function normalizeFilterValue(key: FilterKey, value: string): string {
  const trimmed = value.trim();
  if (key === 'country') {
    return trimmed.toUpperCase();
  }

  return trimmed;
}

export function parseQuery(input: string): ParsedQuery {
  const raw = input;
  const trimmed = input.trim();

  if (trimmed === '') {
    return { filters: {}, q: '', qKind: 'empty', raw };
  }

  const tokens = tokenize(trimmed).map(classifyToken);
  const filters: Partial<Record<FilterKey, string>> = {};
  const qParts: string[] = [];

  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token === undefined) {
      continue;
    }

    if (token.kind === 'pending-key') {
      const next = tokens[i + 1];
      if (next !== undefined && next.kind === 'word') {
        const value = normalizeFilterValue(token.key, next.value);
        if (value !== '') {
          filters[token.key] = value;
        }
        i += 1;
      }
      continue;
    }

    if (token.kind === 'filter') {
      const value = normalizeFilterValue(token.key, token.value);
      if (value !== '') {
        filters[token.key] = value;
      }
      continue;
    }

    const word = token.value.trim();
    if (word !== '') {
      qParts.push(word);
    }
  }

  const q = qParts.join(' ').trim();

  let qKind: ParsedQuery['qKind'] = 'empty';
  if (q !== '') {
    if (qParts.length === 1 && isCIDR(q)) {
      qKind = 'cidr';
    } else if (qParts.length === 1 && (isIPv4(q) || isIPv6(q))) {
      qKind = 'ip';
    } else {
      qKind = 'text';
    }
  }

  return { filters, q, qKind, raw };
}

export function serializeParsed(parsed: ParsedQuery): string {
  const parts: string[] = [];

  for (const key of FILTER_KEYS) {
    const value = parsed.filters[key];
    if (value === undefined || value === '') {
      continue;
    }

    const needsQuote = /\s/.test(value);
    parts.push(`${key}:${needsQuote ? `"${value}"` : value}`);
  }

  if (parsed.q !== '') {
    parts.push(parsed.q);
  }

  return parts.join(' ');
}

export function toURLSearchParams(parsed: ParsedQuery): URLSearchParams {
  const params = new URLSearchParams();

  if (parsed.q !== '') {
    params.set('q', parsed.q);
  }

  for (const key of FILTER_KEYS) {
    const value = parsed.filters[key];
    if (value === undefined || value === '') {
      continue;
    }

    params.set(key, value);
  }

  return params;
}

export function isParsedEmpty(parsed: ParsedQuery): boolean {
  if (parsed.q !== '') {
    return false;
  }

  return FILTER_KEYS.every((k) => {
    const v = parsed.filters[k];

    return v === undefined || v === '';
  });
}
