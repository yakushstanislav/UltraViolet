import * as Dialog from '@radix-ui/react-dialog';
import {
  Activity,
  Bell,
  BellOff,
  CheckCircle2,
  Clock3,
  Plus,
  Terminal,
  Trash2,
  Webhook,
  X,
} from 'lucide-react';
import type { TFunction } from 'i18next';
import {
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';

import { ConfirmDialog } from '@components/ConfirmDialog';
import { DialogSheetContent } from '@components/DialogSheetContent';
import { EmptyState } from '@components/EmptyState';
import { FieldLabel } from '@components/FieldLabel';
import { Select } from '@components/Select';
import { SkeletonRow } from '@components/Skeleton';
import { StatTile, StatTileRow } from '@components/StatTile';
import { Tooltip } from '@components/Tooltip';
import { UvCardList } from '@components/UvCardList';
import { RealtimePanelBadge } from '@components/RealtimePanelBadge';
import { useIsMobile } from '@/hooks/useBreakpoint';
import { useDemoMode } from '@/hooks/useDemoMode';
import { showAlertFiredToast } from '@helpers/realtimeToast';
import { useRealtimeEvents } from '@hooks/useRealtimeEvents';
import { showActionError } from '@helpers/uiError';
import { formatDate } from '@helpers/format';
import { parsePositiveInt } from '@helpers/searchParams';
import {
  createAlert,
  deleteAlert,
  listAlertEvents,
  listAlerts,
  setAlertEnabled,
} from '@services/AlertAPI';
import type { AlertEvent, AlertRule } from '@/types/alerts';
import type { AlertFiredEventData } from '@/types/realtime';
import type { SearchQuery } from '@/types/common';

const DAY_MS = 24 * 60 * 60 * 1000;

function humanizeSeconds(sec: number, translate: TFunction): string {
  if (!Number.isFinite(sec) || sec <= 0) {
    return translate('common.dash');
  }

  if (sec >= 3600) {
    const hours = Math.round(sec / 3600);

    return translate('alerts.cooldownFmtHr', { count: hours });
  }

  if (sec >= 60) {
    const minutes = Math.round(sec / 60);

    return translate('alerts.cooldownFmtMin', { count: minutes });
  }

  return translate('alerts.cooldownFmtSec', { count: sec });
}

function formatRelative(iso: string | undefined, translate: TFunction): string {
  if (!iso) {
    return translate('common.dash');
  }

  const ms = new Date(iso).getTime();

  if (Number.isNaN(ms)) {
    return formatDate(iso);
  }

  const diff = Date.now() - ms;

  if (diff < 0) {
    return formatDate(iso);
  }

  const sec = Math.floor(diff / 1000);

  if (sec < 60) {
    return translate('dashboard.relativeJustNow');
  }

  const min = Math.floor(sec / 60);

  if (min < 60) {
    return translate('dashboard.relativeMinutesAgo', { count: min });
  }

  const hr = Math.floor(min / 60);

  if (hr < 24) {
    return translate('dashboard.relativeHoursAgo', { count: hr });
  }

  return formatDate(iso);
}

function formatRuleQuery(query: SearchQuery | undefined, translate: TFunction): string {
  if (!query) {
    return translate('common.dash');
  }

  if (typeof query.q === 'string' && query.q) {
    return query.q;
  }

  return JSON.stringify(query);
}

function hostFromUrl(url?: string): string {
  if (!url) {
    return '';
  }

  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function ChannelIcon({
  channel,
  size = 14,
}: {
  channel?: string;
  size?: number;
}) {
  if (channel === 'webhook') {
    return <Webhook aria-hidden size={size} />;
  }

  return <Terminal aria-hidden size={size} />;
}

type AlertsKpis = {
  total: number;
  enabled: number;
  fired24h: number;
  lastFire?: string;
};

function computeAlertsKpis(
  rules: AlertRule[],
  events: AlertEvent[],
  rulesTotal: number
): AlertsKpis {
  const total = rulesTotal;
  const enabled = rules.filter((r) => r.enabled).length;

  const now = Date.now();
  const fired24h = events.filter((e) => {
    const t0 = new Date(e.created_at).getTime();

    return !Number.isNaN(t0) && now - t0 < DAY_MS;
  }).length;

  let lastFireMs: number | undefined;

  for (const rule of rules) {
    if (!rule.last_fired_at) {
      continue;
    }

    const t0 = new Date(rule.last_fired_at).getTime();

    if (Number.isNaN(t0)) {
      continue;
    }

    if (lastFireMs === undefined || t0 > lastFireMs) {
      lastFireMs = t0;
    }
  }

  return {
    total,
    enabled,
    fired24h,
    lastFire: lastFireMs ? new Date(lastFireMs).toISOString() : undefined,
  };
}

type AlertsSectionPaginationProps = {
  currentPage: number;
  limit: number;
  limitParam: 'el' | 'limit';
  loading: boolean;
  pageParam: 'ep' | 'page';
  setParams: ReturnType<typeof useSearchParams>[1];
  total: number;
  totalPages: number;
  translate: TFunction;
};

function AlertsSectionPagination({
  currentPage,
  limit,
  limitParam,
  loading,
  pageParam,
  setParams,
  total,
  totalPages,
  translate,
}: AlertsSectionPaginationProps) {
  return (
    <div className="panel pagination-bar alerts-panel-pagination">
      <span className="pagination-bar-meta">
        {translate('hostPage.paginationComma', {
          page: currentPage,
          pages: totalPages,
          total,
        })}
      </span>
      <div className="header-actions pagination-bar-controls">
        <label className="muted-text pagination-bar-limit">
          {translate('scansPage.limitLabel')}
          <Select
            compact
            onChange={(next) => {
              const nextLimit = parsePositiveInt(next, 25);
              setParams((prev) => {
                const nextParams = new URLSearchParams(prev);
                nextParams.set(pageParam, '1');
                nextParams.set(limitParam, String(nextLimit));

                return nextParams;
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
            disabled={currentPage <= 1 || loading}
            onClick={() => {
              setParams((prev) => {
                const next = new URLSearchParams(prev);
                next.set(pageParam, String(currentPage - 1));
                next.set(limitParam, String(limit));

                return next;
              });
            }}
            type="button"
          >
            {translate('common.prev')}
          </button>
          <button
            className="secondary"
            disabled={currentPage >= totalPages || loading}
            onClick={() => {
              setParams((prev) => {
                const next = new URLSearchParams(prev);
                next.set(pageParam, String(currentPage + 1));
                next.set(limitParam, String(limit));

                return next;
              });
            }}
            type="button"
          >
            {translate('common.next')}
          </button>
        </div>
      </div>
    </div>
  );
}

export function AlertsPage() {
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [params, setParams] = useSearchParams();

  const page = parsePositiveInt(params.get('page'), 1);
  const limit = parsePositiveInt(params.get('limit'), 25);
  const ep = parsePositiveInt(params.get('ep'), 1);
  const el = parsePositiveInt(params.get('el'), 25);

  const [rules, setRules] = useState<AlertRule[]>([]);
  const [events, setEvents] = useState<AlertEvent[]>([]);
  const [rulesTotal, setRulesTotal] = useState(0);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [error, setError] = useState('');
  const [rulesRefreshCount, setRulesRefreshCount] = useState(0);
  const [eventsRefreshCount, setEventsRefreshCount] = useState(0);

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState('');
  const [queryText, setQueryText] = useState('');
  const [channel, setChannel] = useState('log');
  const [destination, setDestination] = useState('');
  const [cooldownSec, setCooldownSec] = useState(300);
  const [deletingRule, setDeletingRule] = useState<{
    id: number;
    name: string;
  } | null>(null);

  const alertDebounceRef = useRef<number | null>(null);
  const [highlightedEventIds, setHighlightedEventIds] = useState<Set<number>>(
    new Set(),
  );
  const highlightTimersRef = useRef<Map<number, number>>(new Map());
  const highlightNextRefreshRef = useRef(false);

  const markEventHighlighted = useCallback((eventId: number) => {
    setHighlightedEventIds((current) => {
      const next = new Set(current);
      next.add(eventId);

      return next;
    });

    const existing = highlightTimersRef.current.get(eventId);
    if (existing !== undefined) {
      window.clearTimeout(existing);
    }

    const timer = window.setTimeout(() => {
      highlightTimersRef.current.delete(eventId);
      setHighlightedEventIds((current) => {
        const next = new Set(current);
        next.delete(eventId);

        return next;
      });
    }, 4000);

    highlightTimersRef.current.set(eventId, timer);
  }, []);

  const rulesTotalPages = useMemo(
    () => Math.max(1, Math.ceil(rulesTotal / limit)),
    [limit, rulesTotal]
  );
  const eventsTotalPages = useMemo(
    () => Math.max(1, Math.ceil(eventsTotal / el)),
    [el, eventsTotal]
  );

  useEffect(() => {
    if (rulesLoading || rulesTotal === 0 || page <= rulesTotalPages) {
      return;
    }

    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('page', String(rulesTotalPages));
      next.set('limit', String(limit));

      return next;
    });
  }, [limit, page, rulesLoading, rulesTotal, rulesTotalPages, setParams]);

  useEffect(() => {
    if (eventsLoading || eventsTotal === 0 || ep <= eventsTotalPages) {
      return;
    }

    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('ep', String(eventsTotalPages));
      next.set('el', String(el));

      return next;
    });
  }, [el, ep, eventsLoading, eventsTotal, eventsTotalPages, setParams]);

  useEffect(() => {
    const controller = new AbortController();

    setRulesLoading(true);
    setError('');

    void listAlerts(page, limit)
      .then((response) => {
        if (controller.signal.aborted) {
          return;
        }

        setRules(response.items ?? []);
        setRulesTotal(response.total ?? 0);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        setError(err instanceof Error ? err.message : t('common.loadFailed'));
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setRulesLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [page, limit, rulesRefreshCount, t]);

  useEffect(() => {
    const controller = new AbortController();

    setEventsLoading(true);
    setError('');

    void listAlertEvents(ep, el)
      .then((response) => {
        if (controller.signal.aborted) {
          return;
        }

        const nextEvents = response.items ?? [];

        setEvents(nextEvents);
        setEventsTotal(response.total ?? 0);

        const firstEvent = nextEvents[0];
        if (highlightNextRefreshRef.current && firstEvent !== undefined) {
          highlightNextRefreshRef.current = false;
          markEventHighlighted(firstEvent.id);
        }
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        setError(err instanceof Error ? err.message : t('common.loadFailed'));
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setEventsLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [ep, el, eventsRefreshCount, markEventHighlighted, t]);

  useEffect(() => {
    const timers = highlightTimersRef.current;

    return () => {
      for (const timer of timers.values()) {
        window.clearTimeout(timer);
      }

      timers.clear();
    };
  }, []);

  useRealtimeEvents(['alert.fired'], (event) => {
    const data = event.data as AlertFiredEventData;
    showAlertFiredToast(data, t);
    highlightNextRefreshRef.current = true;

    if (alertDebounceRef.current !== null) {
      window.clearTimeout(alertDebounceRef.current);
    }

    alertDebounceRef.current = window.setTimeout(() => {
      alertDebounceRef.current = null;
      setParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('ep', '1');

        return next;
      });
      setEventsRefreshCount((c) => c + 1);
    }, 1000);
  });

  const resetForm = () => {
    setName('');
    setQueryText('');
    setChannel('log');
    setDestination('');
    setCooldownSec(300);
  };

  const handleCreate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    try {
      await createAlert({
        name,
        q: queryText,
        channel,
        destination,
        cooldown_sec: cooldownSec,
      });
      toast.success(t('toasts.alertCreated'));
      resetForm();
      setCreateOpen(false);
      setRulesRefreshCount((c) => c + 1);
    } catch (err) {
      showActionError(err, 'common.createFailed');
    }
  };

  const commitDelete = async () => {
    if (!deletingRule) {
      return;
    }

    const deletedId = deletingRule.id;
    const snapshot = rules;

    setRules((current) => current.filter((rule) => rule.id !== deletedId));

    try {
      await deleteAlert(deletedId);
      setDeletingRule(null);
      toast.success(t('common.deleted'));
      setRulesRefreshCount((c) => c + 1);
    } catch (err) {
      setRules(snapshot);
      showActionError(err, 'common.deleteFailed');
    }
  };

  const handleToggleEnabled = async (rule: AlertRule) => {
    try {
      await setAlertEnabled(rule.id, !rule.enabled);
      toast.success(
        rule.enabled ? t('toasts.ruleDisabled') : t('toasts.ruleEnabled')
      );
      setRulesRefreshCount((c) => c + 1);
    } catch (err) {
      showActionError(err, 'common.updateFailed');
    }
  };

  const kpis = useMemo(
    () => computeAlertsKpis(rules, events, rulesTotal),
    [rules, events, rulesTotal]
  );
  const demoMode = useDemoMode();

  const showEmptyState = !rulesLoading && rulesTotal === 0;

  return (
    <section className="page alerts-page">
      <StatTileRow>
        <StatTile
          icon={<Bell size={18} />}
          label={t('alerts.rulesTotal')}
          value={kpis.total}
        />
        <StatTile
          icon={<CheckCircle2 size={18} />}
          label={t('alerts.enabled')}
          tone={kpis.enabled > 0 ? 'success' : 'muted'}
          value={
            <>
              {kpis.enabled}
              <span className="alerts-kpi-value-secondary"> / {kpis.total}</span>
            </>
          }
        />
        <StatTile
          icon={<Activity size={18} />}
          label={t('alerts.fired24h')}
          tone={kpis.fired24h > 0 ? 'warning' : 'default'}
          value={kpis.fired24h}
        />
        <StatTile
          icon={<Clock3 size={18} />}
          label={t('alerts.lastFire')}
          tone="muted"
          value={
            <span
              className="alerts-kpi-value-secondary"
              title={kpis.lastFire ? formatDate(kpis.lastFire) : undefined}
            >
              {kpis.lastFire
                ? formatRelative(kpis.lastFire, t)
                : t('common.dash')}
            </span>
          }
        />
      </StatTileRow>

      {error !== '' && <div className="error">{error}</div>}

      <div className="feature-page-stack">
        <div className="panel">
          <div className="panel-head saved-search-lib-head">
            <div className="saved-search-lib-head-meta">
              <h2>{t('alerts.rulesHeading', { count: rulesTotal })}</h2>
              <p className="panel-subtitle">{t('alerts.rulesSubtitle')}</p>
            </div>
            <div className="saved-search-lib-head-tools">
              <button disabled={demoMode} onClick={() => setCreateOpen(true)} type="button">
                <Plus aria-hidden size={16} />
                {t('alerts.newRule')}
              </button>
            </div>
          </div>
          {showEmptyState ? (
            <EmptyState
              action={
                <button disabled={demoMode} onClick={() => setCreateOpen(true)} type="button">
                  <Plus aria-hidden size={16} />
                  {t('common.create')}
                </button>
              }
              hint={t('emptyState.alerts.hint')}
              icon={<BellOff size={28} />}
              title={t('emptyState.alerts.title')}
            />
          ) : isMobile ? (
            <UvCardList
              getRowId={(rule) => rule.id}
              loading={rulesLoading}
              renderCard={(rule) => (
                <>
                  <div className="uv-card__head">
                    <span className="uv-card__title">{rule.name}</span>
                    <Tooltip
                      label={
                        rule.enabled
                          ? t('alerts.disableRule')
                          : t('alerts.enableRule')
                      }
                    >
                      <button
                        aria-label={
                          rule.enabled
                            ? t('alerts.disableRule')
                            : t('alerts.enableRule')
                        }
                        aria-pressed={rule.enabled}
                        className={`toggle-switch${rule.enabled ? ' toggle-switch-on' : ''}`}
                        disabled={demoMode}
                        onClick={() => void handleToggleEnabled(rule)}
                        type="button"
                      >
                        <span className="toggle-switch-thumb" />
                      </button>
                    </Tooltip>
                  </div>
                  <div className="uv-card__meta">
                    <span className="alerts-channel-icon">
                      <ChannelIcon channel={rule.channel} />
                      <span
                        className={
                          rule.channel === 'webhook'
                            ? 'channel-badge'
                            : 'channel-badge channel-badge-muted'
                        }
                      >
                        {rule.channel}
                      </span>
                    </span>
                    {rule.destination ? (
                      <span
                        className="cell-mono alerts-destination"
                        title={rule.destination}
                      >
                        {hostFromUrl(rule.destination) || rule.destination}
                      </span>
                    ) : null}
                    <span>{humanizeSeconds(rule.cooldown_sec, t)}</span>
                    <span
                      title={
                        rule.last_fired_at
                          ? formatDate(rule.last_fired_at)
                          : undefined
                      }
                    >
                      {rule.last_fired_at
                        ? formatRelative(rule.last_fired_at, t)
                        : t('common.dash')}
                    </span>
                  </div>
                  <div className="uv-card__body">
                    <code
                      className="table-json-preview"
                      title={rule.query ? JSON.stringify(rule.query) : undefined}
                    >
                      {formatRuleQuery(rule.query, t)}
                    </code>
                  </div>
                  <div className="uv-card__actions">
                    <button
                      className="secondary"
                      disabled={demoMode}
                      onClick={() =>
                        setDeletingRule({ id: rule.id, name: rule.name })
                      }
                      type="button"
                    >
                      <Trash2 aria-hidden size={14} />
                      {t('common.delete')}
                    </button>
                  </div>
                </>
              )}
              rows={rules}
            />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t('columns.name')}</th>
                    <th>{t('columns.query')}</th>
                    <th>{t('columns.channel')}</th>
                    <th>{t('columns.cooldown')}</th>
                    <th>{t('columns.enabled')}</th>
                    <th>{t('columns.lastFired')}</th>
                    <th>{t('columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rulesLoading &&
                    rules.length === 0 &&
                    [
                      ['long', 'mid', 'short', 'short', 'short', 'mid', 'short'],
                      ['mid', 'long', 'short', 'mid', 'short', 'short', 'mid'],
                      ['short', 'mid', 'long', 'short', 'mid', 'short', 'short'],
                    ].map((cells, index) => (
                      <SkeletonRow
                        cells={
                          cells as Array<'short' | 'mid' | 'long'>
                        }
                        key={`sk-${index}`}
                      />
                    ))}
                  {rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <strong>{rule.name}</strong>
                      </td>
                      <td className="match-cell">
                        <code
                          className="table-json-preview"
                          title={
                            rule.query
                              ? JSON.stringify(rule.query)
                              : undefined
                          }
                        >
                          {formatRuleQuery(rule.query, t)}
                        </code>
                      </td>
                      <td>
                        <div className="alerts-channel-cell">
                          <span className="alerts-channel-icon">
                            <ChannelIcon channel={rule.channel} />
                            <span
                              className={
                                rule.channel === 'webhook'
                                  ? 'channel-badge'
                                  : 'channel-badge channel-badge-muted'
                              }
                            >
                              {rule.channel}
                            </span>
                          </span>
                          {rule.destination ? (
                            <span
                              className="cell-mono alerts-destination"
                              title={rule.destination}
                            >
                              {hostFromUrl(rule.destination) ||
                                rule.destination}
                            </span>
                          ) : null}
                        </div>
                      </td>
                      <td>{humanizeSeconds(rule.cooldown_sec, t)}</td>
                      <td>
                        <Tooltip
                          label={
                            rule.enabled
                              ? t('alerts.disableRule')
                              : t('alerts.enableRule')
                          }
                        >
                          <button
                            aria-label={
                              rule.enabled
                                ? t('alerts.disableRule')
                                : t('alerts.enableRule')
                            }
                            aria-pressed={rule.enabled}
                            className={`toggle-switch${rule.enabled ? ' toggle-switch-on' : ''}`}
                            disabled={demoMode}
                            onClick={() => void handleToggleEnabled(rule)}
                            type="button"
                          >
                            <span className="toggle-switch-thumb" />
                          </button>
                        </Tooltip>
                      </td>
                      <td
                        title={
                          rule.last_fired_at
                            ? formatDate(rule.last_fired_at)
                            : undefined
                        }
                      >
                        {rule.last_fired_at
                          ? formatRelative(rule.last_fired_at, t)
                          : t('common.dash')}
                      </td>
                      <td>
                        <Tooltip label={t('common.delete')}>
                          <button
                            className="secondary"
                            disabled={demoMode}
                            onClick={() =>
                              setDeletingRule({ id: rule.id, name: rule.name })
                            }
                            type="button"
                          >
                            <Trash2 aria-hidden size={14} />
                            {t('common.delete')}
                          </button>
                        </Tooltip>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!showEmptyState ? (
            <AlertsSectionPagination
              currentPage={page}
              limit={limit}
              limitParam="limit"
              loading={rulesLoading}
              pageParam="page"
              setParams={setParams}
              total={rulesTotal}
              totalPages={rulesTotalPages}
              translate={t}
            />
          ) : null}
        </div>

        <div className="panel alerts-events-panel">
          <div className="panel-head">
            <div className="alerts-events-head">
              <h2>
                {t('alerts.eventsHeading', { count: eventsTotal })}
                <RealtimePanelBadge labelKey="realtime.panelStreaming" />
              </h2>
              <p className="panel-subtitle">{t('alerts.eventsSubtitle')}</p>
            </div>
          </div>
          {isMobile ? (
            <UvCardList
              cardClassName={(event) =>
                highlightedEventIds.has(event.id)
                  ? 'uv-card--realtime-new'
                  : undefined
              }
              className="alerts-events-card-list"
              empty={
                eventsLoading ? (
                  <span>{t('common.loading')}</span>
                ) : (
                  <span>{t('alerts.noEvents')}</span>
                )
              }
              getRowId={(event) => event.id}
              loading={eventsLoading}
              renderCard={(event) => {
                const rule = rules.find((r) => r.id === event.rule_id);
                const isNew = highlightedEventIds.has(event.id);
                const full = event.payload
                  ? JSON.stringify(event.payload)
                  : null;

                return (
                  <>
                    <div className="uv-card__head">
                      <span className="uv-card__title">
                        {rule ? (
                          <span className="alerts-channel-icon">
                            <span
                              aria-hidden
                              className="alerts-channel-icon-sm"
                            >
                              <ChannelIcon channel={rule.channel} size={12} />
                            </span>
                            {rule.name}
                          </span>
                        ) : (
                          <span className="cell-mono">{event.rule_id}</span>
                        )}
                      </span>
                      <span
                        className="uv-card__meta-time"
                        title={formatDate(event.created_at)}
                      >
                        {formatRelative(event.created_at, t)}
                      </span>
                    </div>
                    <div className="uv-card__meta">
                      <span>
                        {t('columns.hits')}: {event.hits_count}
                      </span>
                    </div>
                    {full ? (
                      <details className="uv-card__details">
                        <summary>{t('columns.payload')}</summary>
                        <code className="table-json-preview uv-card__payload">
                          {full}
                        </code>
                      </details>
                    ) : null}
                  </>
                );
              }}
              rows={events}
            />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t('columns.time')}</th>
                    <th>{t('columns.rule')}</th>
                    <th>{t('columns.hits')}</th>
                    <th>{t('columns.payload')}</th>
                  </tr>
                </thead>
                <tbody>
                  {eventsLoading && events.length === 0 && (
                  <tr>
                    <td className="table-empty-cell" colSpan={4}>
                      {t('common.loading')}
                    </td>
                  </tr>
                )}
                {!eventsLoading && eventsTotal === 0 && (
                  <tr>
                    <td className="table-empty-cell" colSpan={4}>
                      {t('alerts.noEvents')}
                    </td>
                  </tr>
                )}
                {events.map((event) => {
                  const rule = rules.find((r) => r.id === event.rule_id);

                  const isNew = highlightedEventIds.has(event.id);

                  return (
                    <tr
                      className={
                        isNew ? 'realtime-table-row-new' : undefined
                      }
                      key={event.id}
                    >
                      <td title={formatDate(event.created_at)}>
                        {formatRelative(event.created_at, t)}
                      </td>
                      <td>
                        {rule ? (
                          <span className="alerts-channel-icon">
                            <span
                              aria-hidden
                              className="alerts-channel-icon-sm"
                            >
                              <ChannelIcon channel={rule.channel} size={12} />
                            </span>
                            <strong>{rule.name}</strong>
                          </span>
                        ) : (
                          <span className="cell-mono">{event.rule_id}</span>
                        )}
                      </td>
                      <td>{event.hits_count}</td>
                      <td className="match-cell">
                        {event.payload ? (
                          (() => {
                            const full = JSON.stringify(event.payload);
                            const preview =
                              full.length > 160
                                ? `${full.slice(0, 160)}…`
                                : full;

                            return (
                              <code className="table-json-preview" title={full}>
                                {preview}
                              </code>
                            );
                          })()
                        ) : (
                          <code className="table-json-preview">
                            {t('common.dash')}
                          </code>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          )}
          {eventsTotal > 0 ? (
            <AlertsSectionPagination
              currentPage={ep}
              limit={el}
              limitParam="el"
              loading={eventsLoading}
              pageParam="ep"
              setParams={setParams}
              total={eventsTotal}
              totalPages={eventsTotalPages}
              translate={t}
            />
          ) : null}
        </div>
      </div>

      <ConfirmDialog
        confirmIcon={<Trash2 aria-hidden size={14} />}
        confirmLabel={t('common.delete')}
        onConfirm={commitDelete}
        onOpenChange={(open) => {
          if (!open) {
            setDeletingRule(null);
          }
        }}
        open={deletingRule !== null}
        title={
          deletingRule
            ? t('alerts.deleteConfirm', { name: deletingRule.name })
            : ''
        }
        tone="danger"
      />

      <Dialog.Root onOpenChange={setCreateOpen} open={createOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <DialogSheetContent onDismiss={() => setCreateOpen(false)}>
            <Dialog.Title>{t('alerts.dialogTitle')}</Dialog.Title>
            <Dialog.Description className="panel-subtitle">
              <Trans
                components={{ mono: <span className="cell-mono" /> }}
                i18nKey="alerts.dialogDescriptionRich"
              />
            </Dialog.Description>
            <form onSubmit={handleCreate}>
              <label>
                <FieldLabel required>{t('alerts.name')}</FieldLabel>
                <input
                  aria-required="true"
                  onChange={(event) => setName(event.target.value)}
                  placeholder={t('alerts.namePh')}
                  required
                  value={name}
                />
              </label>
              <label>
                {t('alerts.queryLabel')}
                <input
                  onChange={(event) => setQueryText(event.target.value)}
                  placeholder={t('alerts.queryPh')}
                  value={queryText}
                />
              </label>
              <label>
                {t('alerts.channel')}
                <Select
                  onChange={setChannel}
                  options={[
                    { value: 'log', label: t('alerts.optLog') },
                    { value: 'webhook', label: t('alerts.optWebhook') },
                  ]}
                  value={channel}
                />
              </label>
              <label>
                {t('alerts.destination')}
                <input
                  onChange={(event) => setDestination(event.target.value)}
                  placeholder={
                    channel === 'webhook'
                      ? t('alerts.destPhWebhook')
                      : t('alerts.destPhLog')
                  }
                  value={destination}
                />
                {channel === 'webhook' && (
                  <p className="field-hint">{t('alerts.webhookHint')}</p>
                )}
              </label>
              <label>
                {t('alerts.cooldownShort')}
                <input
                  min={1}
                  onChange={(event) =>
                    setCooldownSec(Number(event.target.value) || 300)
                  }
                  type="number"
                  value={cooldownSec}
                />
              </label>
              <div className="dialog-actions">
                <Dialog.Close asChild>
                  <button className="secondary" type="button">
                    <X aria-hidden size={16} />
                    {t('common.cancel')}
                  </button>
                </Dialog.Close>
                <button type="submit">
                  <Plus aria-hidden size={16} />
                  {t('alerts.createRule')}
                </button>
              </div>
            </form>
          </DialogSheetContent>
        </Dialog.Portal>
      </Dialog.Root>
    </section>
  );
}
