import * as Dialog from '@radix-ui/react-dialog';
import { Search, X } from 'lucide-react';
import {
  Fragment,
  KeyboardEvent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate } from 'react-router-dom';

import {
  Action,
  ActionEffect,
  ActionGroup,
  GROUP_TITLE_KEYS,
  buildActions,
} from './commandPalette/buildActions';
import {
  FILTER_KEYS,
  FilterKey,
  parseQuery,
  serializeParsed,
} from './commandPalette/parseQuery';
import { readRecentHosts } from './commandPalette/recentHosts';
import {
  readSearchHistory,
  rememberSearchQuery,
} from './commandPalette/searchHistory';
import { SheetDragHandle } from './SheetDragHandle';
import { logoutUser } from '@features/Auth/authSlice';
import { countryCodeToFlagEmoji } from '@helpers/countryFlagEmoji';
import { getKbdHint, readKbdHintAriaLabel } from '@helpers/platform';
import { useIsPhablet } from '@/hooks/useBreakpoint';
import { useAppDispatch } from '@store/store';
import { useTheme } from '@/theme/ThemeProvider';

type CommandPaletteProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

const GROUP_ORDER: ActionGroup[] = [
  'host',
  'search',
  'suggestion',
  'recentHost',
  'recent',
  'navigation',
];

function filterChipLabelKey(key: FilterKey): string {
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
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const { t } = useTranslation();
  const isPhablet = useIsPhablet();
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useAppDispatch();
  const { toggleTheme } = useTheme();
  const [value, setValue] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [history, setHistory] = useState<string[]>(() => readSearchHistory());
  const [recentHosts, setRecentHosts] = useState<string[]>(() =>
    readRecentHosts()
  );

  useEffect(() => {
    if (!open) {
      return;
    }

    setValue('');
    setActiveIndex(0);
    setHistory(readSearchHistory());
    setRecentHosts(readRecentHosts());
  }, [open]);

  const parsed = useMemo(() => parseQuery(value), [value]);

  const actions = useMemo(
    () =>
      buildActions({
        input: value,
        parsed,
        history,
        recentHosts,
        currentPath: location.pathname,
        t,
      }),
    [value, parsed, history, recentHosts, location.pathname, t]
  );

  useEffect(() => {
    setActiveIndex(0);
  }, [value]);

  const runEffect = useCallback(
    (effect: ActionEffect) => {
      switch (effect.kind) {
        case 'navigate': {
          if (effect.commit !== undefined) {
            rememberSearchQuery(effect.commit);
          }
          navigate(effect.to);
          onOpenChange(false);
          break;
        }
        case 'replace-input': {
          setValue(effect.value);
          break;
        }
        case 'toggle-theme': {
          toggleTheme();
          onOpenChange(false);
          break;
        }
        case 'logout': {
          void dispatch(logoutUser());
          onOpenChange(false);
          break;
        }
      }
    },
    [dispatch, navigate, onOpenChange, toggleTheme]
  );

  const runActionAt = useCallback(
    (index: number) => {
      const action = actions[index];
      if (!action) {
        return;
      }

      runEffect(action.effect);
    },
    [actions, runEffect]
  );

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      if (actions.length === 0) {
        return;
      }
      setActiveIndex((prev) => (prev + 1) % actions.length);
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      if (actions.length === 0) {
        return;
      }
      setActiveIndex((prev) => (prev - 1 + actions.length) % actions.length);
      return;
    }
    if (event.key === 'Enter') {
      event.preventDefault();
      runActionAt(activeIndex);
      return;
    }
    if (event.key === 'Tab') {
      const firstSuggestion = actions.findIndex(
        (a) => a.group === 'suggestion'
      );
      if (firstSuggestion >= 0) {
        event.preventDefault();
        runActionAt(firstSuggestion);
      }
    }
  };

  const removeFilter = (key: FilterKey) => {
    setValue((current) => {
      const currentParsed = parseQuery(current);

      return serializeParsed({
        ...currentParsed,
        filters: { ...currentParsed.filters, [key]: undefined },
      });
    });
  };

  const clearQuery = () => {
    setValue((current) => {
      const currentParsed = parseQuery(current);

      return serializeParsed({
        ...currentParsed,
        q: '',
        qKind: 'empty' as const,
      });
    });
  };

  const grouped = useMemo(() => {
    const map = new Map<ActionGroup, Action[]>();
    for (const action of actions) {
      const list = map.get(action.group) ?? [];
      list.push(action);
      map.set(action.group, list);
    }
    return map;
  }, [actions]);

  const renderItemLabel = (action: Action) => {
    const colon = action.label.indexOf(':');
    if (
      action.group === 'suggestion' &&
      colon > 0 &&
      colon < action.label.length
    ) {
      const key = action.label.slice(0, colon + 1);
      const rest = action.label.slice(colon + 1);
      return (
        <span className="command-palette-item-label">
          <span className="command-palette-item-key">{key}</span>
          {rest && <span>{rest}</span>}
        </span>
      );
    }

    return <span className="command-palette-item-label">{action.label}</span>;
  };

  const groupOffsets = useMemo(() => {
    const offsets = new Map<ActionGroup, number>();
    let cursor = 0;

    for (const group of GROUP_ORDER) {
      offsets.set(group, cursor);
      cursor += grouped.get(group)?.length ?? 0;
    }

    return offsets;
  }, [grouped]);

  const hasChips =
    FILTER_KEYS.some((k) => parsed.filters[k] !== undefined) || parsed.q !== '';

  const kbdHint = getKbdHint('K');

  return (
    <Dialog.Root onOpenChange={onOpenChange} open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay command-palette-overlay" />
        <Dialog.Content
          aria-describedby={undefined}
          className={`command-palette${isPhablet ? ' uv-dialog--sheet' : ''}`}
        >
          {isPhablet && (
            <SheetDragHandle onDismiss={() => onOpenChange(false)} />
          )}
          <Dialog.Title className="command-palette-title">
            {t('commandPalette.title')}
          </Dialog.Title>
          <div className="command-palette-form">
            <span className="command-palette-prompt">
              <Search size={16} />
            </span>
            <input
              aria-activedescendant={
                actions.length > 0 ? `command-palette-option-${String(activeIndex)}` : undefined
              }
              aria-autocomplete="list"
              aria-controls="command-palette-list"
              autoFocus
              className="command-palette-input"
              onChange={(event) => setValue(event.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={t('commandPalette.placeholder')}
              role="combobox"
              aria-expanded={actions.length > 0}
              type="text"
              value={value}
            />
            <kbd
              aria-label={readKbdHintAriaLabel(kbdHint)}
              className="command-palette-kbd"
            >
              {kbdHint}
            </kbd>
          </div>

          {hasChips && (
            <div className="command-palette-chips">
              {FILTER_KEYS.map((key) => {
                const v = parsed.filters[key];
                if (v === undefined || v === '') {
                  return null;
                }
                return (
                  <button
                    aria-label={t('commandPalette.removeFilter', {
                      label: t(filterChipLabelKey(key)),
                    })}
                    className="command-palette-chip"
                    key={key}
                    onClick={() => removeFilter(key)}
                    type="button"
                  >
                    <span className="command-palette-chip-key">
                      {t(filterChipLabelKey(key))}
                    </span>
                    <span className="command-palette-chip-value">
                      {key === 'country' && (
                        <span aria-hidden className="command-palette-chip-flag">
                          {countryCodeToFlagEmoji(v)}
                        </span>
                      )}
                      {v}
                    </span>
                    <X aria-hidden size={12} />
                  </button>
                );
              })}
              {parsed.q !== '' && (
                <button
                  aria-label={t('commandPalette.removeQuery')}
                  className="command-palette-chip"
                  onClick={clearQuery}
                  type="button"
                >
                  <span className="command-palette-chip-key">
                    {parsed.qKind === 'cidr'
                      ? t('commandPalette.chipCidr')
                      : parsed.qKind === 'ip'
                        ? t('commandPalette.chipIp')
                        : t('commandPalette.chipText')}
                  </span>
                  <span className="command-palette-chip-value">{parsed.q}</span>
                  <X aria-hidden size={12} />
                </button>
              )}
            </div>
          )}

          <div
            aria-label={t('commandPalette.title')}
            className="command-palette-list"
            id="command-palette-list"
            role="listbox"
          >
            {actions.length === 0 && (
              <div className="command-palette-empty">
                {value.trim() === ''
                  ? t('commandPalette.emptyHint')
                  : t('commandPalette.emptyNoMatch')}
              </div>
            )}
            {GROUP_ORDER.map((group) => {
              const items = grouped.get(group);
              if (!items || items.length === 0) {
                return null;
              }

              const groupOffset = groupOffsets.get(group) ?? 0;

              return (
                <Fragment key={group}>
                  <div
                    aria-hidden
                    className="command-palette-section-title"
                  >
                    {t(GROUP_TITLE_KEYS[group])}
                  </div>
                  {items.map((action, itemIndex) => {
                    const index = groupOffset + itemIndex;
                    const Icon = action.icon;
                    const isActive = index === activeIndex;
                    return (
                      // Keyboard navigation is handled by the combobox input
                      // (ArrowUp/ArrowDown/Enter) — see handleKeyDown above.
                      // eslint-disable-next-line jsx-a11y/click-events-have-key-events
                      <div
                        aria-selected={isActive}
                        className="command-palette-item"
                        data-active={isActive ? 'true' : 'false'}
                        id={`command-palette-option-${String(index)}`}
                        key={action.id}
                        onClick={() => runActionAt(index)}
                        onMouseEnter={() => setActiveIndex(index)}
                        role="option"
                        tabIndex={-1}
                      >
                        <span className="command-palette-item-icon">
                          <Icon size={14} />
                        </span>
                        {renderItemLabel(action)}
                        {action.description && (
                          <span className="command-palette-item-description">
                            {action.description}
                          </span>
                        )}
                        {isActive && (
                          <span className="command-palette-item-hint">
                            <kbd aria-label={t('commandPalette.kbdEnter')}>↵</kbd>
                          </span>
                        )}
                      </div>
                    );
                  })}
                </Fragment>
              );
            })}
          </div>

          <div className="command-palette-footer">
            <span>
              <kbd aria-label={t('commandPalette.kbdArrowUp')}>↑</kbd>
              <kbd aria-label={t('commandPalette.kbdArrowDown')}>↓</kbd>{' '}
              {t('commandPalette.footerNavigate')}
            </span>
            <span>
              <kbd aria-label={t('commandPalette.kbdEnter')}>↵</kbd>{' '}
              {t('commandPalette.footerRun')}
            </span>
            <span>
              <kbd>tab</kbd> {t('commandPalette.footerComplete')}
            </span>
            <span>
              <kbd>esc</kbd> {t('commandPalette.footerClose')}
            </span>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
