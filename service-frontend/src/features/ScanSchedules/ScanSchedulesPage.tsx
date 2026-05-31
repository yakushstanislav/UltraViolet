import * as Popover from '@radix-ui/react-popover';
import { CalendarClock, Loader2, Play, Plus, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';

import { ConfirmDialog } from '@components/ConfirmDialog';
import { EmptyState } from '@components/EmptyState';
import { PaginationBarDock } from '@components/PaginationBarDock';
import { Select } from '@components/Select';
import { Tooltip } from '@components/Tooltip';
import { UvCardList } from '@components/UvCardList';
import { useIsMobile } from '@/hooks/useBreakpoint';
import { formatScanScheduleInterval } from '@features/Scans/scanScheduleIntervals';
import { useHasRole } from '@features/Auth/hooks';
import { useDemoMode } from '@/hooks/useDemoMode';
import { resolveScanCreateErrorMessage } from '@helpers/scanCreateApiError';
import { showActionError } from '@helpers/uiError';
import { formatDate } from '@helpers/format';
import { scrollPaginationAnchor } from '@helpers/scrollPaginationAnchor';
import { parsePositiveInt } from '@helpers/searchParams';
import {
  deleteScanSchedule,
  listScanSchedules,
  runScanScheduleNow,
  setScanScheduleEnabled,
} from '@services/ScanScheduleAPI';
import type { ScanSchedule } from '@/types/scanSchedules';

import { ScanScheduleCreateDialog } from './ScanScheduleCreateDialog';

export function ScanSchedulesPage() {
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const canManage = useHasRole('operator');
  const demoMode = useDemoMode();
  const [params, setParams] = useSearchParams();

  const page = parsePositiveInt(params.get('page'), 1);
  const limit = parsePositiveInt(params.get('limit'), 25);

  const [items, setItems] = useState<ScanSchedule[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refreshCount, setRefreshCount] = useState(0);
  const [runningId, setRunningId] = useState<number | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

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
    const controller = new AbortController();

    setLoading(true);
    setError('');

    void listScanSchedules(page, limit)
      .then((response) => {
        if (controller.signal.aborted) {
          return;
        }

        setItems(response.schedules ?? []);
        setTotal(response.total ?? 0);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
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
  }, [page, limit, refreshCount, t]);

  const schedulePendingDelete =
    confirmDeleteId !== null
      ? (items.find((item) => item.id === confirmDeleteId) ?? null)
      : null;

  const commitDelete = async (id: number) => {
    setConfirmDeleteId(null);
    const snapshot = items;
    setItems((current) => current.filter((item) => item.id !== id));

    try {
      await deleteScanSchedule(id);
      toast.success(t('common.deleted'));
      setRefreshCount((c) => c + 1);
    } catch (err) {
      setItems(snapshot);
      showActionError(err, 'common.deleteFailed');
    }
  };

  const handleRun = async (id: number) => {
    setRunningId(id);

    try {
      await runScanScheduleNow(id);
      toast.success(t('scanSchedules.runQueued'));
      setRefreshCount((c) => c + 1);
    } catch (err) {
      toast.error(resolveScanCreateErrorMessage(err, t('common.runFailed')));
    } finally {
      setRunningId(null);
    }
  };

  const toggleEnabled = async (item: ScanSchedule) => {
    try {
      const updated = await setScanScheduleEnabled(item.id, !item.enabled);
      setItems((current) =>
        current.map((row) => (row.id === item.id ? updated : row))
      );
      toast.success(t('scanSchedules.updated'));
    } catch (err) {
      showActionError(err, 'common.updateFailed');
    }
  };

  return (
    <section className="page saved-searches-page scan-schedules-page pagination-bar-scope">
      {error && <div className="error">{error}</div>}
      <div className="feature-page-stack">
        <div className="panel">
          <div className="panel-head saved-search-lib-head">
            <div className="saved-search-lib-head-meta">
              <h2>{t('scanSchedules.title')}</h2>
              <p className="panel-subtitle">{t('scanSchedules.subtitle')}</p>
            </div>
            {canManage && (
              <button
                className="scan-schedules-head-cta"
                disabled={demoMode}
                onClick={() => setCreateOpen(true)}
                type="button"
              >
                <Plus aria-hidden size={16} />
                {t('scanSchedules.newSchedule')}
              </button>
            )}
          </div>
          {isMobile ? (
            <UvCardList
              empty={
                <EmptyState
                  action={
                    canManage && !isMobile ? (
                      <button onClick={() => setCreateOpen(true)} type="button">
                        <Plus aria-hidden size={16} />
                        {t('scanSchedules.newSchedule')}
                      </button>
                    ) : undefined
                  }
                  hint={t('scanSchedules.emptyHint')}
                  icon={<CalendarClock size={28} />}
                  title={t('scanSchedules.emptyTitle')}
                />
              }
              getRowId={(item) => item.id}
              loading={loading}
              renderCard={(item) => (
                <>
                  <div className="uv-card__head">
                    <span className="uv-card__title">{item.name}</span>
                    <span className="muted-text">
                      {item.enabled
                        ? t('scanSchedules.enabledOn')
                        : t('scanSchedules.enabledOff')}
                    </span>
                  </div>
                  <div className="uv-card__meta">
                    <span>{item.target || '—'}</span>
                    <span>
                      {formatScanScheduleInterval(item.interval_seconds, t)}
                    </span>
                    <span>{formatDate(item.next_run_at)}</span>
                  </div>
                  <div className="uv-card__actions header-actions saved-search-actions">
                    {item.last_scan_id ? (
                      <Link
                        className="secondary"
                        to={`/scans/${item.last_scan_id}`}
                      >
                        #{item.last_scan_id}
                      </Link>
                    ) : null}
                    {canManage && (
                      <>
                        <button
                          className="secondary"
                          disabled={demoMode}
                          onClick={() => void toggleEnabled(item)}
                          type="button"
                        >
                          {item.enabled
                            ? t('scanSchedules.enabledOn')
                            : t('scanSchedules.enabledOff')}
                        </button>
                        <button
                          className="saved-search-run"
                          disabled={runningId === item.id || demoMode}
                          onClick={() => void handleRun(item.id)}
                          type="button"
                        >
                          {runningId === item.id ? (
                            <Loader2
                              aria-hidden
                              className="spin"
                              size={14}
                            />
                          ) : (
                            <Play aria-hidden size={14} />
                          )}
                          {t('scanSchedules.runNow')}
                        </button>
                        <button
                          className="ghost saved-search-delete"
                          disabled={demoMode}
                          onClick={() => setConfirmDeleteId(item.id)}
                          type="button"
                        >
                          <Trash2 aria-hidden size={14} />
                          {t('common.delete')}
                        </button>
                      </>
                    )}
                  </div>
                </>
              )}
              rows={items}
            />
          ) : (
            <div className="table-wrap pagination-scroll-anchor">
              <table>
                <thead>
                  <tr>
                    <th>{t('columns.name')}</th>
                    <th>{t('scanSchedules.target')}</th>
                    <th>{t('scanSchedules.interval')}</th>
                    <th>{t('scanSchedules.nextRun')}</th>
                    <th>{t('scanSchedules.enabled')}</th>
                    <th>{t('columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {loading && items.length === 0 && (
                    <tr>
                      <td className="table-empty-cell" colSpan={6}>
                        {t('common.loading')}
                      </td>
                    </tr>
                  )}
                  {!loading && total === 0 && (
                    <tr>
                      <td className="table-empty-cell" colSpan={6}>
                        <EmptyState
                        action={
                          canManage ? (
                            <button
                              disabled={demoMode}
                              onClick={() => setCreateOpen(true)}
                              type="button"
                            >
                              <Plus aria-hidden size={16} />
                              {t('scanSchedules.newSchedule')}
                            </button>
                          ) : undefined
                        }
                        hint={t('scanSchedules.emptyHint')}
                        icon={<CalendarClock size={28} />}
                        title={t('scanSchedules.emptyTitle')}
                      />
                    </td>
                  </tr>
                )}
                {items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <strong>{item.name}</strong>
                    </td>
                    <td>{item.target || '—'}</td>
                    <td>
                      {formatScanScheduleInterval(item.interval_seconds, t)}
                    </td>
                    <td>{formatDate(item.next_run_at)}</td>
                    <td>
                      {canManage ? (
                        <button
                          className="secondary"
                          disabled={demoMode}
                          onClick={() => void toggleEnabled(item)}
                          type="button"
                        >
                          {item.enabled
                            ? t('scanSchedules.enabledOn')
                            : t('scanSchedules.enabledOff')}
                        </button>
                      ) : item.enabled ? (
                        t('scanSchedules.enabledOn')
                      ) : (
                        t('scanSchedules.enabledOff')
                      )}
                    </td>
                    <td className="saved-search-actions-cell">
                      <div className="header-actions saved-search-actions">
                        {item.last_scan_id ? (
                          <Link
                            className="secondary"
                            to={`/scans/${item.last_scan_id}`}
                          >
                            #{item.last_scan_id}
                          </Link>
                        ) : null}
                        {canManage && (
                          <>
                            <button
                              className="saved-search-run"
                              disabled={runningId === item.id || demoMode}
                              onClick={() => void handleRun(item.id)}
                              type="button"
                            >
                              {runningId === item.id ? (
                                <Loader2
                                  aria-hidden
                                  className="spin"
                                  size={14}
                                />
                              ) : (
                                <Play aria-hidden size={14} />
                              )}
                              {t('scanSchedules.runNow')}
                            </button>
                            <Popover.Root
                              onOpenChange={(open) => {
                                setConfirmDeleteId(open ? item.id : null);
                              }}
                              open={confirmDeleteId === item.id}
                            >
                              <Tooltip label={t('common.delete')}>
                                <Popover.Trigger asChild>
                                  <button
                                    className="ghost saved-search-delete"
                                    disabled={demoMode}
                                    type="button"
                                  >
                                    <Trash2 aria-hidden size={14} />
                                  </button>
                                </Popover.Trigger>
                              </Tooltip>
                              <Popover.Portal>
                                <Popover.Content
                                  align="end"
                                  className="saved-search-delete-popover"
                                  side="bottom"
                                  sideOffset={6}
                                >
                                  <div className="saved-search-delete-popover-inner">
                                    <p className="saved-search-delete-popover-title">
                                      {t('scanSchedules.deleteConfirm', {
                                        name: item.name,
                                      })}
                                    </p>
                                    <div className="saved-search-delete-popover-actions">
                                      <Popover.Close asChild>
                                        <button
                                          className="secondary"
                                          type="button"
                                        >
                                          {t('common.cancel')}
                                        </button>
                                      </Popover.Close>
                                      <button
                                        className="danger"
                                        onClick={() => void commitDelete(item.id)}
                                        type="button"
                                      >
                                        {t('common.delete')}
                                      </button>
                                    </div>
                                  </div>
                                </Popover.Content>
                              </Popover.Portal>
                            </Popover.Root>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          )}
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
                      const nextParams = new URLSearchParams(prev);
                      nextParams.set('page', '1');
                      nextParams.set('limit', String(nextLimit));

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

      {canManage ? (
        <ScanScheduleCreateDialog
          onCreated={() => setRefreshCount((c) => c + 1)}
          onOpenChange={setCreateOpen}
          open={createOpen}
        />
      ) : null}

      {isMobile && (
        <ConfirmDialog
          confirmIcon={<Trash2 aria-hidden size={14} />}
          confirmLabel={t('common.delete')}
          onConfirm={() => {
            if (confirmDeleteId !== null) {
              void commitDelete(confirmDeleteId);
            }
          }}
          onOpenChange={(open) => {
            if (!open) {
              setConfirmDeleteId(null);
            }
          }}
          open={schedulePendingDelete !== null}
          title={
            schedulePendingDelete
              ? t('scanSchedules.deleteConfirm', {
                  name: schedulePendingDelete.name,
                })
              : ''
          }
          tone="danger"
        />
      )}
    </section>
  );
}
