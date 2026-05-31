import type { TFunction } from 'i18next';
import {
  Activity,
  Clock,
  CornerDownLeft,
  Globe,
  LayoutGrid,
  LogOut,
  Search,
  Server,
  SunMoon,
  TerminalSquare,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import {
  FILTER_KEYS,
  FilterKey,
  ParsedQuery,
  isParsedEmpty,
  parseQuery,
  serializeParsed,
  toURLSearchParams,
} from './parseQuery';
import { countryCodeToFlagEmoji } from '@helpers/countryFlagEmoji';
import { COUNTRY_OPTIONS } from '@helpers/countryOptions';

export type ActionEffect =
  | { kind: 'navigate'; to: string; commit?: string }
  | { kind: 'replace-input'; value: string }
  | { kind: 'toggle-theme' }
  | { kind: 'logout' };

export type ActionGroup =
  | 'host'
  | 'search'
  | 'suggestion'
  | 'recentHost'
  | 'recent'
  | 'navigation';

export type Action = {
  id: string;
  group: ActionGroup;
  icon: LucideIcon;
  label: string;
  description?: string;
  hint?: string;
  effect: ActionEffect;
};

const filterLabelKey = (key: FilterKey): string => {
  switch (key) {
    case 'port':
      return 'commandPalette.filterPort';
    case 'country':
      return 'commandPalette.filterCountry';
    case 'asn':
      return 'commandPalette.filterAsn';
    case 'protocol':
      return 'commandPalette.filterProtocol';
    case 'tls_issuer':
      return 'commandPalette.filterTlsIssuer';
    case 'tls_fingerprint':
      return 'commandPalette.filterTlsFingerprint';
    default:
      return key;
  }
};

const keyDescriptionKey = (key: FilterKey): string => {
  switch (key) {
    case 'port':
      return 'commandPalette.keyDescPort';
    case 'country':
      return 'commandPalette.keyDescCountry';
    case 'asn':
      return 'commandPalette.keyDescAsn';
    case 'protocol':
      return 'commandPalette.keyDescProtocol';
    case 'tls_issuer':
      return 'commandPalette.keyDescTlsIssuer';
    case 'tls_fingerprint':
      return 'commandPalette.keyDescTlsFingerprint';
    default:
      return key;
  }
};

function summarizeParsed(parsed: ParsedQuery, t: TFunction): string {
  const parts: string[] = [];

  for (const key of FILTER_KEYS) {
    const value = parsed.filters[key];
    if (value === undefined || value === '') {
      continue;
    }

    parts.push(`${t(filterLabelKey(key))} ${value}`);
  }

  if (parsed.q !== '') {
    if (parsed.qKind === 'cidr') {
      parts.push(t('commandPalette.summarizeCidr', { q: parsed.q }));
    } else if (parsed.qKind === 'ip') {
      parts.push(t('commandPalette.summarizeIp', { q: parsed.q }));
    } else {
      parts.push(t('commandPalette.summarizeText', { q: parsed.q }));
    }
  }

  return parts.join(' · ');
}

function lastToken(input: string): string {
  const trimmedEnd = input.replace(/\s+$/, '');
  if (trimmedEnd !== input) {
    return '';
  }

  const idx = input.lastIndexOf(' ');

  return idx === -1 ? input : input.slice(idx + 1);
}

function replaceLastToken(input: string, replacement: string): string {
  const idx = input.lastIndexOf(' ');
  if (idx === -1) {
    return replacement;
  }

  return `${input.slice(0, idx + 1)}${replacement}`;
}

function keySuggestions(
  input: string,
  parsed: ParsedQuery,
  token: string,
  t: TFunction
): Action[] {
  if (token === '' || token.includes(':')) {
    return [];
  }

  const tokenLower = token.toLowerCase();
  if (!/^[a-z_]+$/.test(tokenLower)) {
    return [];
  }

  const used = new Set(
    FILTER_KEYS.filter((k) => parsed.filters[k] !== undefined)
  );

  const matches = FILTER_KEYS.filter(
    (k) => k.startsWith(tokenLower) && !used.has(k)
  );

  return matches.slice(0, 6).map((key) => ({
    id: `suggest-key-${key}`,
    group: 'suggestion' as const,
    icon: TerminalSquare,
    label: `${key}:`,
    description: t(keyDescriptionKey(key)),
    hint: 'Tab',
    effect: {
      kind: 'replace-input' as const,
      value: replaceLastToken(input, `${key}:`),
    },
  }));
}

function countrySuggestions(input: string, token: string): Action[] {
  if (!token.toLowerCase().startsWith('country:')) {
    return [];
  }

  const valuePrefix = token.slice('country:'.length).toUpperCase();
  const candidates = COUNTRY_OPTIONS.filter((opt) => {
    if (valuePrefix === '') {
      return true;
    }

    return (
      opt.code.startsWith(valuePrefix) ||
      opt.name.toUpperCase().startsWith(valuePrefix)
    );
  }).slice(0, 6);

  return candidates.map((opt) => ({
    id: `suggest-country-${opt.code}`,
    group: 'suggestion' as const,
    icon: Globe,
    label: `country:${opt.code}`,
    description: `${countryCodeToFlagEmoji(opt.code)} ${opt.name}`,
    hint: 'Tab',
    effect: {
      kind: 'replace-input' as const,
      value: `${replaceLastToken(input, `country:${opt.code}`)} `,
    },
  }));
}

export type BuildActionsContext = {
  input: string;
  parsed: ParsedQuery;
  history: string[];
  recentHosts: string[];
  currentPath: string;
  t: TFunction;
};

export function buildActions(ctx: BuildActionsContext): Action[] {
  const { input, parsed, history, recentHosts, currentPath, t } = ctx;
  const actions: Action[] = [];
  const hasInput = input.trim() !== '';
  const empty = isParsedEmpty(parsed);

  if (hasInput && parsed.qKind === 'ip' && empty === false && parsed.q !== '') {
    const noFiltersBesidesIP = FILTER_KEYS.every((k) => {
      const v = parsed.filters[k];

      return v === undefined || v === '';
    });
    if (noFiltersBesidesIP) {
      actions.push({
        id: 'host-open',
        group: 'host',
        icon: CornerDownLeft,
        label: t('commandPalette.openHost', { ip: parsed.q }),
        description: t('commandPalette.openHostDesc', { ip: parsed.q }),
        effect: {
          kind: 'navigate',
          to: `/hosts/${encodeURIComponent(parsed.q)}`,
          commit: parsed.q,
        },
      });
    }
  }

  if (hasInput && empty === false) {
    const params = toURLSearchParams(parsed);
    const to = `/search?${params.toString()}`;
    actions.push({
      id: 'search-run',
      group: 'search',
      icon: Search,
      label: t('commandPalette.runSearch'),
      description: summarizeParsed(parsed, t),
      effect: { kind: 'navigate', to, commit: serializeParsed(parsed) },
    });
  }

  if (hasInput) {
    const token = lastToken(input);
    actions.push(...countrySuggestions(input, token));
    actions.push(...keySuggestions(input, parsed, token, t));
  }

  if (!hasInput && recentHosts.length > 0) {
    for (const ip of recentHosts.slice(0, 5)) {
      actions.push({
        id: `recent-host-${ip}`,
        group: 'recentHost',
        icon: Server,
        label: ip,
        description: t('commandPalette.openHostDesc', { ip }),
        effect: {
          kind: 'navigate',
          to: `/hosts/${encodeURIComponent(ip)}`,
        },
      });
    }
  }

  if (!hasInput && history.length > 0) {
    for (const entry of history) {
      const parsedEntry = parseQuery(entry);
      const params = toURLSearchParams(parsedEntry);
      actions.push({
        id: `recent-${entry}`,
        group: 'recent',
        icon: Clock,
        label: entry,
        description: summarizeParsed(parsedEntry, t) || undefined,
        effect: {
          kind: 'navigate',
          to: `/search?${params.toString()}`,
          commit: entry,
        },
      });
    }
  }

  if (!hasInput) {
    const nav: Action[] = [
      {
        id: 'nav-overview',
        group: 'navigation',
        icon: LayoutGrid,
        label: t('commandPalette.navOverview'),
        description: '/dashboard',
        effect: { kind: 'navigate', to: '/dashboard' },
      },
      {
        id: 'nav-search',
        group: 'navigation',
        icon: Search,
        label: t('commandPalette.navSearch'),
        description: '/search',
        effect: { kind: 'navigate', to: '/search' },
      },
      {
        id: 'nav-jobs',
        group: 'navigation',
        icon: Activity,
        label: t('commandPalette.navJobs'),
        description: '/scans',
        effect: { kind: 'navigate', to: '/scans' },
      },
      {
        id: 'nav-toggle-theme',
        group: 'navigation',
        icon: SunMoon,
        label: t('commandPalette.navToggleTheme'),
        effect: { kind: 'toggle-theme' },
      },
      {
        id: 'nav-logout',
        group: 'navigation',
        icon: LogOut,
        label: t('commandPalette.navLogout'),
        effect: { kind: 'logout' },
      },
    ];

    actions.push(
      ...nav.filter(
        (a) => a.effect.kind !== 'navigate' || a.effect.to !== currentPath
      )
    );
  }

  return actions;
}

export const GROUP_TITLE_KEYS: Record<ActionGroup, string> = {
  host: 'commandPalette.groupHost',
  search: 'commandPalette.groupSearch',
  suggestion: 'commandPalette.groupSuggestion',
  recentHost: 'commandPalette.recentHostsTitle',
  recent: 'commandPalette.groupRecent',
  navigation: 'commandPalette.groupNavigation',
};
