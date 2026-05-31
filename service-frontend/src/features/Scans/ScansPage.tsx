import * as Dialog from '@radix-ui/react-dialog';
import {
  Activity,
  Plus,
  Search,
  StopCircle,
  X,
} from 'lucide-react';
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ConfirmDialog } from '@components/ConfirmDialog';
import { DialogSheetContent } from '@components/DialogSheetContent';
import { PaginationBarDock } from '@components/PaginationBarDock';
import { EmptyState } from '@components/EmptyState';
import { InlineError } from '@components/InlineError';
import { Select } from '@components/Select';
import { SkeletonRow } from '@components/Skeleton';
import { SortableHeader } from '@components/SortableHeader';
import { UvCardList } from '@components/UvCardList';
import { useIsMobile } from '@/hooks/useBreakpoint';
import { useDemoMode } from '@/hooks/useDemoMode';
import { useTableKeyboardNav } from '@/hooks/useTableKeyboardNav';
import { formatDate, formatPortsExpr, formatScanMode } from '@helpers/format';
import { showActionError, showActionSuccess } from '@helpers/uiError';
import i18n from '@i18n/i18n';
import { hostPathFromScanTarget } from '@helpers/hostPathFromScanTarget';
import { rememberScanTarget } from '@helpers/recentScanTargets';
import { generateRandomScanName } from '@helpers/randomScanName';
import { scrollPaginationAnchor } from '@helpers/scrollPaginationAnchor';
import { parsePositiveInt } from '@helpers/searchParams';
import type { ScanFormValues } from '@schemas/scan';
import { useAppDispatch, useAppSelector } from '@store/store';
import { ScanCreateFormBody } from './ScanCreateFormBody';
import { scanFormValuesToScanPayload } from './scanFormPayload';
import { SCAN_CREATE_FORM_DEFAULTS } from './scanFormDefaults';
import { useScanCreateForm } from './useScanCreateForm';
import { loadScans, stopScan, submitScan } from './scansActions';
import {
  defaultOrderForSort,
  parseListOrder,
  parseListSort,
  parseStatusFilter,
  type ListSortKey,
  type ListOrder,
  type ScanStatusFilter,
} from './scansListParams';
import { CountryTargetBadge } from './CountryTargetBadge';
import { RandomTargetBadge } from './RandomTargetBadge';
import { resetScans } from './scansSlice';
import { ScanStatusBadge } from './ScanStatusBadge';
import { toNonNegativeCount } from './scanStatsHelpers';
import { useStatusFlash } from '@/hooks/useStatusFlash';
import { useVisibilityPolling } from '@/hooks/useVisibilityPolling';

const SCAN_TABLE_SKELETON_ROWS: Array<Array<'short' | 'mid' | 'long'>> = [
  ['short', 'long', 'short', 'mid', 'short', 'mid', 'mid'],
  ['short', 'mid', 'long', 'short', 'mid', 'short', 'mid'],
  ['mid', 'short', 'long', 'mid', 'short', 'mid', 'short'],
  ['short', 'long', 'mid', 'short', 'long', 'short', 'mid'],
  ['short', 'mid', 'short', 'long', 'mid', 'mid', 'short'],
  ['mid', 'long', 'short', 'mid', 'short', 'long', 'mid'],
];

export function ScansPage() {
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const { items, page, limit, total, loading, refreshing, creating, error } =
    useAppSelector((state) => state.scans);
  const busy = loading || refreshing;
  const [params, setParams] = useSearchParams();
  const statusFromParams = params.get('status');
  const pageFromParams = parsePositiveInt(params.get('page'), 1);
  const limitFromParams = parsePositiveInt(params.get('limit'), 25);
  const sortFromParams = parseListSort(params.get('sort'));
  const orderFromParams = parseListOrder(params.get('order'));
  const listSortKey: ListSortKey = sortFromParams ?? 'id';
  const listOrder: ListOrder = orderFromParams ?? 'desc';
  const role = useAppSelector((state) => state.auth.role);
  const canCreate = role === 'operator' || role === 'admin';
  const demoMode = useDemoMode();
  const [open, setOpen] = useState(false);
  const [statusFilter, setStatusFilter] = useState<ScanStatusFilter>(() =>
    parseStatusFilter(statusFromParams)
  );
  const [searchValue, setSearchValue] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulkCancelOpen, setBulkCancelOpen] = useState(false);
  const [bulkSubmitting, setBulkSubmitting] = useState(false);
  const flashedScanIds = useStatusFlash(items);
  const scanForm = useScanCreateForm({ open });
  const { form, setScanDialogContentEl } = scanForm;

  const refreshScans = useCallback(async () => {
    await dispatch(
      loadScans({
        page: pageFromParams,
        limit: limitFromParams,
        sort: sortFromParams,
        order: orderFromParams,
      })
    );
  }, [
    dispatch,
    limitFromParams,
    orderFromParams,
    pageFromParams,
    sortFromParams,
  ]);

  useEffect(() => {
    void refreshScans();
  }, [refreshScans]);

  useEffect(() => {
    return () => {
      dispatch(resetScans());
    };
  }, [dispatch]);

  const hasActiveScans = items.some(
    (s) =>
      s.status === 'RUNNING' || s.status === 'PENDING' || s.status === 'PAUSED'
  );

  const pollScans = useCallback(() => {
    void refreshScans();
  }, [refreshScans]);

  useVisibilityPolling(pollScans, {
    enabled: hasActiveScans,
    intervalMs: 4000,
  });

  useEffect(() => {
    setStatusFilter(parseStatusFilter(statusFromParams));
  }, [statusFromParams]);

  const filteredItems = useMemo(() => {
    const query = searchValue.trim().toLowerCase();
    return items.filter((scan) => {
      const matchesStatus =
        statusFilter === 'all' || scan.status.toLowerCase() === statusFilter;

      if (!matchesStatus) {
        return false;
      }

      if (query === '') {
        return true;
      }

      return (
        (scan.name ?? '').toLowerCase().includes(query) ||
        (scan.cidr ?? '').toLowerCase().includes(query) ||
        String(scan.id).includes(query)
      );
    });
  }, [items, searchValue, statusFilter]);

  const cancellableSelectedIds = useMemo(
    () =>
      filteredItems
        .filter(
          (scan) =>
            selectedIds.has(scan.id) &&
            (scan.status === 'RUNNING' ||
              scan.status === 'PENDING' ||
              scan.status === 'PAUSED')
        )
        .map((scan) => scan.id),
    [filteredItems, selectedIds]
  );

  useEffect(() => {
    setSelectedIds((current) => {
      if (current.size === 0) {
        return current;
      }

      const visible = new Set(filteredItems.map((scan) => scan.id));
      const next = new Set<number>();

      for (const id of current) {
        if (visible.has(id)) {
          next.add(id);
        }
      }

      return next.size === current.size ? current : next;
    });
  }, [filteredItems]);

  const toggleRowSelect = useCallback((id: number) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }

      return next;
    });
  }, []);

  const allFilteredSelected =
    filteredItems.length > 0 &&
    filteredItems.every((scan) => selectedIds.has(scan.id));
  const someFilteredSelected =
    filteredItems.some((scan) => selectedIds.has(scan.id)) &&
    !allFilteredSelected;

  const toggleAllVisible = useCallback(() => {
    setSelectedIds((current) => {
      if (filteredItems.length === 0) {
        return current;
      }

      const allOn = filteredItems.every((scan) => current.has(scan.id));

      if (allOn) {
        const next = new Set(current);
        for (const scan of filteredItems) {
          next.delete(scan.id);
        }
        return next;
      }

      const next = new Set(current);
      for (const scan of filteredItems) {
        next.add(scan.id);
      }
      return next;
    });
  }, [filteredItems]);

  const rowIds = useMemo(
    () => filteredItems.map((scan) => scan.id),
    [filteredItems]
  );

  const { activeId } = useTableKeyboardNav<number>({
    rowIds,
    onActivate: (id) => navigate(`/scans/${id}`),
    onToggleSelect: toggleRowSelect,
  });

  const handleBulkCancel = async () => {
    if (cancellableSelectedIds.length === 0) {
      setBulkCancelOpen(false);
      return;
    }

    setBulkSubmitting(true);
    const failures: number[] = [];
    try {
      for (const id of cancellableSelectedIds) {
        try {
          await dispatch(stopScan(id)).unwrap();
        } catch {
          failures.push(id);
        }
      }
    } finally {
      setBulkSubmitting(false);
    }

    if (failures.length > 0) {
      showActionError(
        null,
        i18n.t('scansPage.toastBulkCancelFailed', { count: failures.length })
      );
    } else {
      showActionSuccess('scansPage.toastBulkCancelOk', {
        count: cancellableSelectedIds.length,
      });
    }

    setSelectedIds(new Set());
    setBulkCancelOpen(false);
    void refreshScans();
  };

  const setListSort = (column: ListSortKey) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      const currentSort = parseListSort(prev.get('sort')) ?? 'id';
      const currentOrder = parseListOrder(prev.get('order')) ?? 'desc';

      if (currentSort === column) {
        next.set('order', currentOrder === 'desc' ? 'asc' : 'desc');
      } else {
        next.set('sort', column);
        next.set('order', defaultOrderForSort(column));
      }

      next.set('page', '1');

      return next;
    });
  };

  const create = async (values: ScanFormValues) => {
    if (!canCreate) {
      showActionError(null, 'scansPage.toastCreateInsufficient');
      return;
    }

    try {
      const result = await dispatch(
        submitScan(scanFormValuesToScanPayload(values))
      ).unwrap();
      showActionSuccess('scansPage.toastQueued', { count: result.queued });

      setOpen(false);
      if (values.targetStrategy === 'sequential' && values.target) {
        rememberScanTarget(values.target);
      }

      form.reset({
        ...SCAN_CREATE_FORM_DEFAULTS,
        target: values.targetStrategy === 'sequential' ? values.target : '',
        hostLimit: values.hostLimit,
        name: generateRandomScanName(),
      });
      void refreshScans();
    } catch (error: unknown) {
      showActionError(error, 'scansPage.toastCreateFailed');
    }
  };

  return (
    <section className="page scans-page pagination-bar-scope">
      <div
        className={`panel scans-toolbar ${canCreate ? 'scans-toolbar-with-create' : ''}`}
      >
        <div className="segmented-control" role="tablist">
          {(
            [
              'all',
              'running',
              'pending',
              'paused',
              'failed',
              'canceled',
              'done',
            ] as const
          ).map((value) => (
            <button
              aria-selected={statusFilter === value}
              className={
                statusFilter === value ? 'segmented-active' : 'secondary'
              }
              key={value}
              onClick={() => {
                setStatusFilter(value);

                if (value === 'all') {
                  setParams((prev) => {
                    const next = new URLSearchParams(prev);
                    next.delete('status');
                    next.set('page', '1');
                    return next;
                  });
                  return;
                }

                setParams((prev) => {
                  const next = new URLSearchParams(prev);
                  next.set('status', value);
                  next.set('page', '1');
                  return next;
                });
              }}
              role="tab"
              type="button"
            >
              {value === 'all' ? t('scansPage.statusAll') : value.toUpperCase()}
            </button>
          ))}
        </div>
        <label className="scans-search">
          <Search size={15} />
          <input
            autoComplete="off"
            onChange={(event) => setSearchValue(event.target.value)}
            placeholder={t('scansPage.searchPlaceholder')}
            value={searchValue}
          />
        </label>
        {canCreate && (
          <div className="scans-toolbar-new">
            <Dialog.Root onOpenChange={setOpen} open={open}>
              <Dialog.Trigger asChild>
                <button disabled={demoMode} type="button">
                  <Plus size={16} />
                  {t('scansPage.newScan')}
                </button>
              </Dialog.Trigger>
              <Dialog.Portal>
                <Dialog.Overlay className="dialog-overlay" />
                <DialogSheetContent
                  onDismiss={() => setOpen(false)}
                  ref={setScanDialogContentEl}
                >
                  <Dialog.Title>{t('scansPage.dialogTitle')}</Dialog.Title>
                  <form onSubmit={form.handleSubmit(create)}>
                    <ScanCreateFormBody scanForm={scanForm} />
                    <div className="dialog-actions">
                      <Dialog.Close asChild>
                        <button className="secondary" type="button">
                          <X size={16} />
                          {t('common.cancel')}
                        </button>
                      </Dialog.Close>
                      <button disabled={creating} type="submit">
                        {t('common.create')}
                      </button>
                    </div>
                  </form>
                </DialogSheetContent>
              </Dialog.Portal>
            </Dialog.Root>
          </div>
        )}
      </div>
      {!canCreate && (
        <div className="notice">{t('scansPage.viewerNotice')}</div>
      )}
      {error && (
        <InlineError
          message={error}
          onRetry={() => {
            void refreshScans();
          }}
        />
      )}
      <div className="table-wrap scans-table-wrap pagination-scroll-anchor">
        {isMobile ? (
          <UvCardList
            activeId={activeId}
            cardClassName={(scan) => (selectedIds.has(scan.id) ? 'row-selected' : '')}
            empty={
              items.length === 0 ? (
                <EmptyState
                  action={
                    canCreate ? (
                      <button disabled={demoMode} onClick={() => setOpen(true)} type="button">
                        <Plus aria-hidden size={16} />
                        {t('scansPage.newScan')}
                      </button>
                    ) : undefined
                  }
                  hint={t('emptyState.scans.hint')}
                  icon={<Activity size={28} />}
                  title={t('emptyState.scans.title')}
                />
              ) : (
                <span>{t('scansPage.emptyNoMatch')}</span>
              )
            }
            getRowId={(scan) => scan.id}
            loading={loading}
            onRowActivate={(scan) => navigate(`/scans/${scan.id}`)}
            onToggleSelect={toggleRowSelect}
            renderCard={(scan, ctx) => {
              const errCount = toNonNegativeCount(scan.stats?.errors);
              const doneWithErrors =
                scan.status === 'DONE' && errCount > 0;
              const hostPath = scan.cidr
                ? hostPathFromScanTarget(scan.cidr)
                : null;

              return (
                <>
                  <div className="uv-card__head scans-mobile-card__head">
                    {ctx.selectionInput !== null && (
                      <span className="uv-card__select-wrap">
                        {ctx.selectionInput}
                      </span>
                    )}
                    <span className="uv-card__title">
                      {scan.name || t('scansPage.defaultScanName')}
                    </span>
                    <ScanStatusBadge
                      doneWithErrors={doneWithErrors}
                      flashed={flashedScanIds.includes(scan.id)}
                      status={scan.status}
                    />
                  </div>
                  <div className="uv-card__meta">
                    <span className="cell-mono">#{scan.id}</span>
                    {scan.target_strategy === 'random' ? (
                      <RandomTargetBadge hostLimit={scan.host_limit} />
                    ) : scan.target_strategy === 'country' ? (
                      <CountryTargetBadge
                        country={scan.country ?? ''}
                        hostLimit={scan.host_limit}
                      />
                    ) : hostPath ? (
                      <Link
                        className="cell-mono"
                        onClick={(event) => event.stopPropagation()}
                        to={hostPath}
                      >
                        {scan.cidr}
                      </Link>
                    ) : (
                      <span className="cell-mono">{scan.cidr}</span>
                    )}
                    <span>
                      {formatScanMode(
                        scan.mode,
                        scan.target_strategy,
                        scan.slow_profile
                      )}
                    </span>
                  </div>
                  <div className="uv-card__body">
                    <span className="muted-text cell-mono">
                      {formatPortsExpr(scan.ports_expr)}
                    </span>
                    <span className="muted-text cell-mono">
                      {formatDate(scan.created_at)}
                    </span>
                    {scan.status === 'RUNNING' && scan.cancel_requested && (
                      <span
                        className="muted-text scan-cancel-pending"
                        title={t('scansPage.stopPendingTitle')}
                      >
                        {t('scansPage.stopping')}
                      </span>
                    )}
                    {scan.status === 'RUNNING' && scan.pause_requested && (
                      <span
                        className="muted-text scan-cancel-pending"
                        title={t('scansPage.pausePendingTitle')}
                      >
                        {t('scansPage.pausing')}
                      </span>
                    )}
                  </div>
                </>
              );
            }}
            rows={filteredItems}
            selectable
            selectedIds={selectedIds}
          />
        ) : (
        <table className="scans-table">
          <thead>
            <tr>
              <th className="uv-table-select-col">
                <input
                  aria-label={t('scansPage.selectAll')}
                  checked={allFilteredSelected}
                  disabled={filteredItems.length === 0}
                  onChange={toggleAllVisible}
                  ref={(el) => {
                    if (el) {
                      el.indeterminate = someFilteredSelected;
                    }
                  }}
                  type="checkbox"
                />
              </th>
              <SortableHeader
                activeSortKey={listSortKey}
                ariaLabel={t('scansPage.sortById')}
                label={t('columns.id')}
                onSort={(key) => setListSort(key as ListSortKey)}
                order={listOrder}
                sortButtonClassName="scans-table-sort-btn"
                sortKey="id"
              />
              <th>{t('columns.name')}</th>
              <SortableHeader
                activeSortKey={listSortKey}
                ariaLabel={t('scansPage.sortByStatus')}
                label={t('columns.status')}
                onSort={(key) => setListSort(key as ListSortKey)}
                order={listOrder}
                sortButtonClassName="scans-table-sort-btn"
                sortKey="status"
              />
              <th>{t('columns.ip')}</th>
              <th>{t('columns.mode')}</th>
              <th>{t('columns.ports')}</th>
              <SortableHeader
                activeSortKey={listSortKey}
                ariaLabel={t('scansPage.sortByCreated')}
                label={t('columns.created')}
                onSort={(key) => setListSort(key as ListSortKey)}
                order={listOrder}
                sortButtonClassName="scans-table-sort-btn"
                sortKey="created_at"
              />
            </tr>
          </thead>
          <tbody>
            {loading &&
              SCAN_TABLE_SKELETON_ROWS.map((cells, index) => (
                <SkeletonRow
                  cells={['short', ...cells] as typeof cells}
                  key={`sk-${index}`}
                />
              ))}
            {!loading &&
              filteredItems.map((scan) => {
                const errCount = toNonNegativeCount(scan.stats?.errors);
                const doneWithErrors = scan.status === 'DONE' && errCount > 0;
                const hostPath = scan.cidr
                  ? hostPathFromScanTarget(scan.cidr)
                  : null;
                const isActive = activeId === scan.id;
                const isSelected = selectedIds.has(scan.id);

                return (
                  <tr
                    className={[
                      'scan-row-clickable',
                      isActive ? 'row-active' : '',
                      isSelected ? 'row-selected' : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                    key={scan.id}
                    onClick={() => navigate(`/scans/${scan.id}`)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        navigate(`/scans/${scan.id}`);
                      }
                    }}
                  >
                    <td
                      className="uv-table-select-col"
                      onClick={(event) => event.stopPropagation()}
                    >
                      <input
                        aria-label={t('scansPage.selectRow', { id: scan.id })}
                        checked={isSelected}
                        onChange={() => toggleRowSelect(scan.id)}
                        type="checkbox"
                      />
                    </td>
                    <td className="cell-mono">{scan.id}</td>
                    <td>{scan.name || t('scansPage.defaultScanName')}</td>
                    <td>
                      <div className="scan-status-cell">
                        <ScanStatusBadge
                          doneWithErrors={doneWithErrors}
                          flashed={flashedScanIds.includes(scan.id)}
                          status={scan.status}
                        />
                        {scan.status === 'RUNNING' && scan.cancel_requested && (
                          <span
                            className="muted-text scan-cancel-pending"
                            title={t('scansPage.stopPendingTitle')}
                          >
                            {t('scansPage.stopping')}
                          </span>
                        )}
                        {scan.status === 'RUNNING' && scan.pause_requested && (
                          <span
                            className="muted-text scan-cancel-pending"
                            title={t('scansPage.pausePendingTitle')}
                          >
                            {t('scansPage.pausing')}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="cell-mono">
                      {scan.target_strategy === 'random' ? (
                        <RandomTargetBadge hostLimit={scan.host_limit} />
                      ) : scan.target_strategy === 'country' ? (
                        <CountryTargetBadge
                          country={scan.country ?? ''}
                          hostLimit={scan.host_limit}
                        />
                      ) : hostPath ? (
                        <Link
                          onClick={(event) => event.stopPropagation()}
                          to={hostPath}
                        >
                          {scan.cidr}
                        </Link>
                      ) : (
                        scan.cidr
                      )}
                    </td>
                    <td>
                      {formatScanMode(
                        scan.mode,
                        scan.target_strategy,
                        scan.slow_profile
                      )}
                    </td>
                    <td>{formatPortsExpr(scan.ports_expr)}</td>
                    <td className="cell-mono">{formatDate(scan.created_at)}</td>
                  </tr>
                );
              })}
            {!loading && filteredItems.length === 0 && (
              <tr>
                <td className="table-empty-cell" colSpan={8}>
                  {items.length === 0 ? (
                    <EmptyState
                      action={
                        canCreate ? (
                          <button disabled={demoMode} onClick={() => setOpen(true)} type="button">
                            <Plus aria-hidden size={16} />
                            {t('scansPage.newScan')}
                          </button>
                        ) : undefined
                      }
                      hint={t('emptyState.scans.hint')}
                      icon={<Activity size={28} />}
                      title={t('emptyState.scans.title')}
                    />
                  ) : (
                    t('scansPage.emptyNoMatch')
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        )}
      </div>
      {selectedIds.size > 0 && (
        <div className="uv-bulk-bar" role="region" aria-live="polite">
          <span className="uv-bulk-bar-count">
            {t('scansPage.bulkSelected', { count: selectedIds.size })}
          </span>
          <div className="uv-bulk-bar-actions">
            <button
              className="secondary"
              onClick={() => setSelectedIds(new Set())}
              type="button"
            >
              {t('scansPage.bulkClear')}
            </button>
            <button
              className="danger"
              disabled={
                cancellableSelectedIds.length === 0 || bulkSubmitting
              }
              onClick={() => setBulkCancelOpen(true)}
              type="button"
            >
              <StopCircle size={14} />
              {t('scansPage.bulkCancel', {
                count: cancellableSelectedIds.length,
              })}
            </button>
          </div>
        </div>
      )}

      <ConfirmDialog
        cancelLabel={t('common.cancel')}
        confirmIcon={<StopCircle size={16} />}
        confirmLabel={t('scansPage.bulkCancel', {
          count: cancellableSelectedIds.length,
        })}
        description={t('scansPage.bulkCancelConfirm', {
          count: cancellableSelectedIds.length,
        })}
        icon={<StopCircle size={20} />}
        onConfirm={handleBulkCancel}
        onOpenChange={setBulkCancelOpen}
        open={bulkCancelOpen}
        title={t('scansPage.bulkCancelTitle')}
        tone="danger"
      />

      <PaginationBarDock alignToScope>
      <div className="panel pagination-bar">
        <span className="pagination-bar-meta">
          {t('scansPage.pagination', {
            page,
            pages: Math.max(1, Math.ceil(total / limit)),
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
              value={String(limitFromParams)}
            />
          </label>
          <div className="pagination-bar-nav">
            <button
              className="secondary"
              disabled={page <= 1 || busy}
              onClick={() => {
                setParams((prev) => {
                  const next = new URLSearchParams(prev);
                  next.set('page', String(pageFromParams - 1));
                  next.set('limit', String(limitFromParams));
                  return next;
                });
              }}
              type="button"
            >
              {t('common.prev')}
            </button>
            <button
              className="secondary"
              disabled={page >= Math.max(1, Math.ceil(total / limit)) || busy}
              onClick={() => {
                setParams((prev) => {
                  const next = new URLSearchParams(prev);
                  next.set('page', String(pageFromParams + 1));
                  next.set('limit', String(limitFromParams));
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
    </section>
  );
}
