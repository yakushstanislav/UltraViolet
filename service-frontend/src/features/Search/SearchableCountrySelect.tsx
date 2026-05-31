import clsx from 'clsx';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { countryCodeToFlagEmoji } from '@helpers/countryFlagEmoji';
import {
  COUNTRY_OPTIONS,
  getCountryLabel,
  type CountryOption,
} from '@helpers/countryOptions';

type Props = {
  name: string;
  value: string;
  onChange?: (code: string) => void;
  placeholder?: string;
  showAny?: boolean;
};

function normalizeCode(raw: string): string {
  if (raw.length !== 2) {
    return raw;
  }

  return raw.toUpperCase();
}

export function SearchableCountrySelect({
  name,
  value,
  onChange,
  placeholder,
  showAny = true,
}: Props) {
  const { t } = useTranslation();
  const idBase = useId();
  const listId = `${idBase}-listbox`;
  const searchInputId = `${idBase}-search`;
  const triggerDomId = `${idBase}-trigger`;
  const rootRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [draft, setDraft] = useState(() => normalizeCode(value));
  const [highlighted, setHighlighted] = useState(0);

  useEffect(() => {
    setDraft(normalizeCode(value));
  }, [value]);

  const anyOption = useMemo(
    (): CountryOption => ({ code: '', name: t('searchCountry.anyCountry') }),
    [t]
  );

  const baseList = useMemo(() => {
    const upper = normalizeCode(draft);

    if (!upper || !/^[A-Z]{2}$/.test(upper)) {
      return COUNTRY_OPTIONS;
    }

    if (COUNTRY_OPTIONS.some((o) => o.code === upper)) {
      return COUNTRY_OPTIONS;
    }

    return [{ code: upper, name: getCountryLabel(upper) }, ...COUNTRY_OPTIONS];
  }, [draft]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();

    const matches = (o: CountryOption) => {
      if (!q) {
        return true;
      }

      return (
        o.code.toLowerCase().includes(q) || o.name.toLowerCase().includes(q)
      );
    };

    const head = showAny && matches(anyOption) ? [anyOption] : [];
    const rest = baseList.filter((o) => matches(o));

    return [...head, ...rest];
  }, [anyOption, baseList, query, showAny]);

  useEffect(() => {
    setHighlighted(0);
  }, [query, open, filtered.length]);

  useEffect(() => {
    if (!open) {
      return;
    }

    const onDocMouseDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false);
        setQuery('');
      }
    };

    const onEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') {
        return;
      }

      event.preventDefault();
      setOpen(false);
      setQuery('');
      queueMicrotask(() => {
        document.getElementById(triggerDomId)?.focus();
      });
    };

    document.addEventListener('mousedown', onDocMouseDown);
    document.addEventListener('keydown', onEscape);

    return () => {
      document.removeEventListener('mousedown', onDocMouseDown);
      document.removeEventListener('keydown', onEscape);
    };
  }, [open, triggerDomId]);

  useEffect(() => {
    if (!open) {
      return;
    }

    const id = requestAnimationFrame(() => {
      searchInputRef.current?.focus();
    });

    return () => cancelAnimationFrame(id);
  }, [open]);

  useEffect(() => {
    if (!open || filtered.length === 0) {
      return;
    }

    document.getElementById(`${listId}-opt-${highlighted}`)?.scrollIntoView({
      block: 'nearest',
    });
  }, [highlighted, listId, open, filtered.length]);

  const pickCountry = (code: string) => {
    setDraft(normalizeCode(code));
    onChange?.(normalizeCode(code));
    setOpen(false);
    setQuery('');
    queueMicrotask(() => {
      document.getElementById(triggerDomId)?.focus();
    });
  };

  const { triggerDisplay, triggerTitle } = useMemo(() => {
    if (!draft) {
      return {
        triggerDisplay: placeholder ?? t('search.fields.country'),
        triggerTitle: t('searchCountry.selectCountry'),
      };
    }

    const flag = countryCodeToFlagEmoji(draft);
    const countryName = getCountryLabel(draft);
    const compact = `${flag ? `${flag}\u00A0` : ''}${countryName}`;
    const full = `${flag ? `${flag} ` : ''}${countryName} (${draft})`;

    return { triggerDisplay: compact, triggerTitle: full };
  }, [draft, placeholder, t]);

  const maxIndex = Math.max(0, filtered.length - 1);

  const onSearchKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setHighlighted((h) =>
        filtered.length === 0 ? 0 : Math.min(h + 1, maxIndex)
      );

      return;
    }

    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setHighlighted((h) => Math.max(h - 1, 0));

      return;
    }

    if (event.key === 'Enter') {
      event.preventDefault();
      const opt = filtered[highlighted];

      if (opt) {
        pickCountry(opt.code);
      }
    }
  };

  return (
    <div className="search-country-select" ref={rootRef}>
      <input name={name} type="hidden" value={draft} />
      <div className="search-country-field">
        {open ? (
          <div className="search-country-input-wrap">
            <input
              aria-activedescendant={
                filtered.length > 0 ? `${listId}-opt-${highlighted}` : undefined
              }
              aria-autocomplete="list"
              aria-controls={listId}
              aria-expanded
              autoComplete="off"
              className="search-country-combobox-input"
              id={searchInputId}
              onChange={(event) => setQuery(event.currentTarget.value)}
              onKeyDown={onSearchKeyDown}
              placeholder={t('searchCountry.searchPh')}
              ref={searchInputRef}
              role="combobox"
              type="text"
              value={query}
            />
            <ChevronUp
              aria-hidden
              className="search-country-combobox-caret"
              size={18}
            />
          </div>
        ) : (
          <button
            aria-controls={listId}
            aria-expanded={false}
            aria-haspopup="listbox"
            aria-label={
              draft
                ? t('searchCountry.countryNamedAria', { detail: triggerTitle })
                : t('searchCountry.countryAria')
            }
            className="search-country-trigger"
            data-empty={draft ? undefined : true}
            id={triggerDomId}
            onClick={() => setOpen(true)}
            role="combobox"
            title={draft ? triggerTitle : undefined}
            type="button"
          >
            <span className="search-country-trigger-text">
              {triggerDisplay}
            </span>
            <ChevronDown
              aria-hidden
              className="search-country-trigger-caret"
              size={18}
            />
          </button>
        )}
      </div>
      {open && (
        <div className="search-country-panel" role="presentation">
          <ul className="search-country-list" id={listId} role="listbox">
            {filtered.length === 0 ? (
              <li className="search-country-empty" role="presentation">
                {t('searchCountry.noMatches')}
              </li>
            ) : (
              filtered.map((opt, index) => (
                <li
                  aria-selected={index === highlighted}
                  className={clsx(
                    'search-country-option',
                    index === highlighted && 'search-country-option-active'
                  )}
                  id={`${listId}-opt-${index}`}
                  key={opt.code === '' ? '__any__' : opt.code}
                  onMouseDown={(event) => event.preventDefault()}
                  onMouseEnter={() => setHighlighted(index)}
                  onMouseUp={() => pickCountry(opt.code)}
                  role="option"
                >
                  {opt.code ? (
                    <span aria-hidden className="search-country-option-flag">
                      {countryCodeToFlagEmoji(opt.code)}
                    </span>
                  ) : null}
                  <span className="search-country-option-name">{opt.name}</span>
                  {opt.code ? (
                    <span className="search-country-option-code">
                      {opt.code}
                    </span>
                  ) : null}
                </li>
              ))
            )}
          </ul>
        </div>
      )}
    </div>
  );
}
