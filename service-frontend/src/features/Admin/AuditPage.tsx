import { isAxiosError } from 'axios';
import { Search, Shield, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';

import { CopyButton } from '@components/CopyButton';
import { EmptyState } from '@components/EmptyState';
import { PaginationBarDock } from '@components/PaginationBarDock';
import { Select } from '@components/Select';
import { SkeletonRow } from '@components/Skeleton';
import { Tooltip } from '@components/Tooltip';
import { UvCardList } from '@components/UvCardList';
import { useIsMobile } from '@/hooks/useBreakpoint';
import { formatDate, formatRelative } from '@helpers/format';
import { scrollPaginationAnchor } from '@helpers/scrollPaginationAnchor';
import { parsePositiveInt } from '@helpers/searchParams';
import { listAuditEvents } from '@services/AuditAPI';
import type { AuditEvent, AuditStatusFamily } from '@/types/audit';

import { HttpMethodBadge } from './HttpMethodBadge';
import { HttpStatusBadge } from './HttpStatusBadge';
import { ResourceChip } from './ResourceChip';

const STATUS_FAMILIES: ReadonlyArray<'all' | AuditStatusFamily> = [
  'all',
  '2xx',
  '3xx',
  '4xx',
  '5xx',
];

const AUDIT_TABLE_SKELETON_ROWS: Array<
  Array<'short' | 'mid' | 'long'>
> = [
  ['short', 'mid', 'long', 'short'],
  ['short', 'long', 'mid', 'short'],
  ['mid', 'short', 'long', 'short'],
  ['short', 'mid', 'long', 'short'],
  ['short', 'short', 'long', 'short'],
  ['short', 'long', 'mid', 'short'],
];

const SEARCH_DEBOUNCE_MS = 250;

function parseStatusFamily(
  raw: string | null
): AuditStatusFamily | undefined {
  if (raw === '2xx' || raw === '3xx' || raw === '4xx' || raw === '5xx') {
    return raw;
  }
  return undefined;
}

function rowAccentClass(code: number): string {
  if (code >= 500) return 'audit-row audit-row-5xx';
  if (code >= 400) return 'audit-row audit-row-4xx';
  if (code >= 300) return 'audit-row audit-row-3xx';
  if (code >= 200) return 'audit-row audit-row-2xx';
  return 'audit-row';
}

export function AuditPage() {
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [params, setParams] = useSearchParams();
  const [items, setItems] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const page = parsePositiveInt(params.get('page'), 1);
  const limit = parsePositiveInt(params.get('limit'), 25);
  const statusFamily = parseStatusFamily(params.get('status_family'));
  const qParam = params.get('q') ?? '';

  const [searchInput, setSearchInput] = useState(qParam);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(total / limit)),
    [limit, total]
  );

  useEffect(() => {
    if (loading || total === 0 || page <= totalPages) {
      return;
    }

    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('page', String(totalPages));
      next.set('limit', String(limit));
      return next;
    });
  }, [limit, loading, page, setParams, total, totalPages]);

  useEffect(() => {
    if (searchInput === qParam) {
      return;
    }

    const handle = window.setTimeout(() => {
      setParams((prev) => {
        const next = new URLSearchParams(prev);
        if (searchInput === '') {
          next.delete('q');
        } else {
          next.set('q', searchInput);
        }
        next.set('page', '1');
        return next;
      });
    }, SEARCH_DEBOUNCE_MS);

    return () => {
      window.clearTimeout(handle);
    };
  }, [qParam, searchInput, setParams]);

  useEffect(() => {
    const controller = new AbortController();

    setLoading(true);
    setError('');

    void listAuditEvents(
      {
        page,
        limit,
        status_family: statusFamily,
        q: qParam || undefined,
      },
      controller.signal
    )
      .then((response) => {
        if (controller.signal.aborted) {
          return;
        }

        setItems(response.items ?? []);
        setTotal(response.total ?? 0);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        if (isAxiosError(err) && err.code === 'ERR_CANCELED') {
          return;
        }

        setError(err instanceof Error ? err.message : t('common.loadFailed'));
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [limit, page, qParam, statusFamily, t]);

  const setStatusFamily = (value: 'all' | AuditStatusFamily) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value === 'all') {
        next.delete('status_family');
      } else {
        next.set('status_family', value);
      }
      next.set('page', '1');
      return next;
    });
  };

  const hasActiveFilter = statusFamily !== undefined || qParam !== '';

  const clearFilters = () => {
    setSearchInput('');
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('status_family');
      next.delete('q');
      next.set('page', '1');
      return next;
    });
  };

  return (
    <section className="page admin-audit-page pagination-bar-scope">
      {error && <div className="error">{error}</div>}
      <div className="feature-page-stack">
        <div className="panel audit-panel">
          <header className="audit-header">
            <div className="audit-header-title">
              <h2>
                <Shield aria-hidden size={16} />
                {t('adminAudit.title')}
              </h2>
              <p className="panel-subtitle">{t('adminAudit.subtitle')}</p>
            </div>
          </header>
          <div className="audit-toolbar">
            <div className="segmented-control audit-status-filter" role="tablist">
              {STATUS_FAMILIES.map((value) => {
                const active =
                  value === 'all'
                    ? statusFamily === undefined
                    : statusFamily === value;
                const labelKey =
                  value === 'all'
                    ? 'adminAudit.statusFamilyAll'
                    : (`adminAudit.statusFamily${value}` as const);
                return (
                  <button
                    aria-selected={active}
                    className={active ? 'segmented-active' : 'secondary'}
                    key={value}
                    onClick={() => setStatusFamily(value)}
                    role="tab"
                    type="button"
                  >
                    {t(labelKey)}
                  </button>
                );
              })}
            </div>
            <label className="audit-search">
              <Search aria-hidden size={14} />
              <input
                autoComplete="off"
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder={t('adminAudit.searchPlaceholder')}
                type="search"
                value={searchInput}
              />
            </label>
            {hasActiveFilter && (
              <button
                className="secondary audit-clear-filter"
                onClick={clearFilters}
                type="button"
              >
                <X aria-hidden size={14} />
                {t('adminAudit.clearFilter')}
              </button>
            )}
          </div>
          <div className="table-wrap audit-table-wrap pagination-scroll-anchor">
            {isMobile ? (
              <UvCardList
                cardClassName={(event) => rowAccentClass(event.status_code)}
                empty={
                  hasActiveFilter ? (
                    <div className="audit-empty-filter">
                      {t('adminAudit.noFilterMatch')}
                    </div>
                  ) : (
                    <EmptyState
                      hint={t('adminAudit.emptyHint')}
                      icon={<Shield size={28} />}
                      title={t('adminAudit.emptyTitle')}
                    />
                  )
                }
                getRowId={(event) => event.id}
                loading={loading}
                renderCard={(event) => (
                  <>
                    <div className="audit-event-card__head">
                      <div className="audit-event-card__top">
                        <HttpMethodBadge method={event.method} />
                        <HttpStatusBadge code={event.status_code} />
                      </div>
                      <p className="audit-path-text cell-mono" title={event.path}>
                        {event.path}
                      </p>
                    </div>
                    <div className="audit-event-card__meta">
                      <span className="audit-meta-chip audit-time">
                        {formatRelative(event.created_at)}
                      </span>
                      <span className="audit-meta-chip audit-actor-id">
                        {event.user_id ?? '—'}
                      </span>
                      {event.actor_role && (
                        <span
                          className={`audit-meta-chip audit-actor-role audit-actor-role-${event.actor_role.toLowerCase()}`}
                        >
                          {event.actor_role}
                        </span>
                      )}
                      {event.actor_ip && (
                        <span className="audit-meta-chip audit-actor-ip cell-mono">
                          {event.actor_ip}
                        </span>
                      )}
                    </div>
                    {event.resource_id && (
                      <div className="audit-event-card__resource">
                        <ResourceChip value={event.resource_id} />
                      </div>
                    )}
                  </>
                )}
                rows={items}
              />
            ) : (
              <table className="audit-table">
                <thead>
                  <tr>
                    <th className="audit-time-col">
                      {t('adminAudit.timestamp')}
                    </th>
                    <th>{t('adminAudit.actor')}</th>
                    <th>{t('adminAudit.action')}</th>
                    <th className="audit-status-col">
                      {t('adminAudit.status')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {loading &&
                    items.length === 0 &&
                    AUDIT_TABLE_SKELETON_ROWS.map((cells, index) => (
                      <SkeletonRow cells={cells} key={`sk-${index}`} />
                    ))}
                  {!loading && total === 0 && !hasActiveFilter && (
                    <tr>
                      <td className="table-empty-cell" colSpan={4}>
                        <EmptyState
                          hint={t('adminAudit.emptyHint')}
                          icon={<Shield size={28} />}
                          title={t('adminAudit.emptyTitle')}
                        />
                      </td>
                    </tr>
                  )}
                  {!loading && total === 0 && hasActiveFilter && (
                    <tr>
                      <td className="table-empty-cell" colSpan={4}>
                        <div className="audit-empty-filter">
                          {t('adminAudit.noFilterMatch')}
                        </div>
                      </td>
                    </tr>
                  )}
                  {!loading &&
                    items.map((event) => (
                      <tr
                        className={rowAccentClass(event.status_code)}
                        key={event.id}
                      >
                        <td className="audit-time-col">
                          <Tooltip label={formatDate(event.created_at)}>
                            <span className="audit-time">
                              {formatRelative(event.created_at)}
                            </span>
                          </Tooltip>
                        </td>
                        <td>
                          <div className="audit-actor">
                            <span className="audit-actor-id">
                              {event.user_id ?? '—'}
                            </span>
                            {event.actor_role && (
                              <span
                                className={`audit-actor-role audit-actor-role-${event.actor_role.toLowerCase()}`}
                              >
                                {event.actor_role}
                              </span>
                            )}
                            {event.actor_ip && (
                              <span className="audit-actor-ip cell-mono">
                                {event.actor_ip}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="match-cell">
                          <span className="audit-action-cell">
                            <HttpMethodBadge method={event.method} />
                            {event.user_agent ? (
                              <Tooltip
                                label={`${t('adminAudit.userAgent')}: ${event.user_agent}`}
                              >
                                <span className="audit-path-text cell-mono">
                                  {event.path}
                                </span>
                              </Tooltip>
                            ) : (
                              <span className="audit-path-text cell-mono">
                                {event.path}
                              </span>
                            )}
                            {event.resource_id && (
                              <ResourceChip value={event.resource_id} />
                            )}
                            <CopyButton
                              className="secondary audit-path-copy"
                              iconOnly
                              label={t('adminAudit.copyPath')}
                              size={12}
                              text={event.path}
                            />
                          </span>
                        </td>
                        <td className="audit-status-col">
                          <HttpStatusBadge code={event.status_code} />
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
        <PaginationBarDock alignToScope>
          <div className="panel pagination-bar">
            <span className="pagination-bar-meta">
              {t('hostPage.paginationComma', {
                page,
                pages: totalPages,
                total,
              })}
            </span>
            <div className="header-actions pagination-bar-controls">
              <label className="muted-text pagination-bar-limit">
                {t('scansPage.limitLabel')}
                <Select
                  compact
                  onChange={(next) => {
                    const nextLimit = parsePositiveInt(next, 25);
                    setParams((prev) => {
                      const params = new URLSearchParams(prev);
                      params.set('page', '1');
                      params.set('limit', String(nextLimit));
                      return params;
                    });
                  }}
                  options={[25, 50, 100].map((value) => ({
                    label: String(value),
                    value: String(value),
                  }))}
                  value={String(limit)}
                />
              </label>
              <div className="pagination-bar-nav">
                <button
                  className="secondary"
                  disabled={page <= 1 || loading}
                onClick={() => {
                  setParams((prev) => {
                    const next = new URLSearchParams(prev);
                    next.set('page', String(page - 1));
                    next.set('limit', String(limit));
                    return next;
                  });
                }}
                type="button"
              >
                {t('common.prev')}
              </button>
              <button
                className="secondary"
                disabled={page >= totalPages || loading}
                onClick={() => {
                  setParams((prev) => {
                    const next = new URLSearchParams(prev);
                    next.set('page', String(page + 1));
                    next.set('limit', String(limit));
                    return next;
                  });
                  requestAnimationFrame(() => scrollPaginationAnchor());
                }}
                type="button"
              >
                {t('common.next')}
              </button>
              </div>
            </div>
          </div>
        </PaginationBarDock>
      </div>
    </section>
  );
}
