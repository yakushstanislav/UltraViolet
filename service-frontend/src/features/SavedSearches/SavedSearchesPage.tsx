import * as Dialog from '@radix-ui/react-dialog';
import * as Popover from '@radix-ui/react-popover';
import {
  BookmarkPlus,
  ChevronDown,
  ChevronUp,
  Loader2,
  Play,
  Plus,
  Trash2,
  X,
} from 'lucide-react';
import {
  type FormEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';

import { DialogSheetContent } from '@components/DialogSheetContent';
import { EmptyState } from '@components/EmptyState';
import { PaginationBarDock } from '@components/PaginationBarDock';
import { Select } from '@components/Select';
import { Tooltip } from '@components/Tooltip';
import { UvCardList } from '@components/UvCardList';
import { useIsMobile } from '@/hooks/useBreakpoint';
import { useDemoMode } from '@/hooks/useDemoMode';
import { showActionError } from '@helpers/uiError';
import { formatDate } from '@helpers/format';
import { scrollPaginationAnchor } from '@helpers/scrollPaginationAnchor';
import { parsePositiveInt } from '@helpers/searchParams';
import {
  createSavedSearch,
  deleteSavedSearch,
  listSavedSearches,
  runSavedSearch,
} from '@services/SavedSearchAPI';
import type { SavedSearch } from '@/types/savedSearches';

import {
  CVE_SEVERITIES,
  buildSavedSearchQuery,
  renderLastRun,
  renderQueryTags,
} from './savedSearchHelpers';

export function SavedSearchesPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const isMobile = useIsMobile();
  const demoMode = useDemoMode();
  const [params, setParams] = useSearchParams();

  const page = parsePositiveInt(params.get('page'), 1);
  const limit = parsePositiveInt(params.get('limit'), 25);

  const [items, setItems] = useState<SavedSearch[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [refreshCount, setRefreshCount] = useState(0);
  const [filterText, setFilterText] = useState('');
  const [runningId, setRunningId] = useState<number | null>(null);
  const runNonceRef = useRef(0);
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);

  const [formName, setFormName] = useState('');
  const [formQ, setFormQ] = useState('');
  const [formPort, setFormPort] = useState('');
  const [formCountry, setFormCountry] = useState('');
  const [formProtocol, setFormProtocol] = useState('');
  const [formASN, setFormASN] = useState('');
  const [formHasCVE, setFormHasCVE] = useState('');
  const [formCVESeverity, setFormCVESeverity] = useState('');
  const [formTLSIssuer, setFormTLSIssuer] = useState('');
  const [formTLSFingerprint, setFormTLSFingerprint] = useState('');
  const [formRiskMin, setFormRiskMin] = useState('');
  const [formRiskMax, setFormRiskMax] = useState('');
  const [formLastSeenFrom, setFormLastSeenFrom] = useState('');
  const [formLastSeenTo, setFormLastSeenTo] = useState('');

  const resetForm = () => {
    setFormName('');
    setFormQ('');
    setFormPort('');
    setFormCountry('');
    setFormProtocol('');
    setFormASN('');
    setFormHasCVE('');
    setFormCVESeverity('');
    setFormTLSIssuer('');
    setFormTLSFingerprint('');
    setFormRiskMin('');
    setFormRiskMax('');
    setFormLastSeenFrom('');
    setFormLastSeenTo('');
    setAdvancedOpen(false);
  };

  const buildQueryFromForm = () =>
    buildSavedSearchQuery({
      q: formQ,
      port: formPort,
      country: formCountry,
      protocol: formProtocol,
      asn: formASN,
      hasCve: formHasCVE,
      cveSeverity: formCVESeverity,
      tlsIssuer: formTLSIssuer,
      tlsFingerprint: formTLSFingerprint,
      riskMin: formRiskMin,
      riskMax: formRiskMax,
      lastSeenFrom: formLastSeenFrom,
      lastSeenTo: formLastSeenTo,
    });

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

    void listSavedSearches(page, limit)
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

  const handleCreate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const query = buildQueryFromForm();

    if (Object.keys(query).length === 0) {
      showActionError(null, 'toasts.savedSearchFilter');

      return;
    }

    try {
      await createSavedSearch(formName, query);
      toast.success(t('toasts.savedSearchCreated'));
      resetForm();
      setCreateOpen(false);
      setRefreshCount((c) => c + 1);
    } catch (err) {
      showActionError(err, 'common.createFailed');
    }
  };

  const commitDelete = async (id: number) => {
    const snapshot = items;
    setItems((current) => current.filter((item) => item.id !== id));

    try {
      await deleteSavedSearch(id);
      setConfirmDeleteId(null);
      toast.success(t('common.deleted'));
      setRefreshCount((c) => c + 1);
    } catch (err) {
      setItems(snapshot);
      showActionError(err, 'common.deleteFailed');
    }
  };

  const handleRun = async (id: number) => {
    const myNonce = runNonceRef.current + 1;
    runNonceRef.current = myNonce;
    setRunningId(id);

    try {
      const result = await runSavedSearch(id);

      if (myNonce !== runNonceRef.current) {
        return;
      }

      const params = new URLSearchParams();

      Object.entries(result.query ?? {}).forEach(([key, value]) => {
        if (value !== '' && value !== null && value !== undefined) {
          params.set(key, String(value));
        }
      });

      navigate(`/search?${params.toString()}`);
    } catch (err) {
      if (myNonce !== runNonceRef.current) {
        return;
      }

      showActionError(err, 'common.runFailed');
    } finally {
      if (myNonce === runNonceRef.current) {
        setRunningId(null);
      }
    }
  };

  const filtered = filterText
    ? items.filter((i) =>
        i.name.toLowerCase().includes(filterText.toLowerCase())
      )
    : items;

  const skeletonRows = useMemo(
    () =>
      Array.from({ length: 3 }, (_, index) => (
        <tr className="saved-skeleton-row" key={index}>
          <td>
            <span className="saved-skeleton-bar saved-skeleton-bar-name" />
          </td>
          <td>
            <div className="saved-skeleton-chips">
              <span className="saved-skeleton-bar saved-skeleton-bar-chip" />
              <span className="saved-skeleton-bar saved-skeleton-bar-chip" />
              <span className="saved-skeleton-bar saved-skeleton-bar-chip" />
            </div>
          </td>
          <td>
            <span className="saved-skeleton-bar saved-skeleton-bar-short" />
          </td>
          <td>
            <span className="saved-skeleton-bar saved-skeleton-bar-short" />
          </td>
          <td>
            <span className="saved-skeleton-bar saved-skeleton-bar-actions" />
          </td>
        </tr>
      )),
    []
  );

  const renderSavedSearchActions = (item: SavedSearch) => (
    <div className="header-actions saved-search-actions">
      <button
        className="saved-search-run"
        disabled={runningId === item.id}
        onClick={() => void handleRun(item.id)}
        type="button"
      >
        {runningId === item.id ? (
          <Loader2 aria-hidden className="spin" size={14} />
        ) : (
          <Play aria-hidden size={14} />
        )}
        {t('savedSearches.run')}
      </button>
      <Popover.Root
        onOpenChange={(open) => {
          if (open) {
            setConfirmDeleteId(item.id);

            return;
          }

          setConfirmDeleteId((prev) => (prev === item.id ? null : prev));
        }}
        open={confirmDeleteId === item.id}
      >
        <Tooltip label={t('savedSearches.deleteTitle')}>
          <Popover.Trigger asChild>
            <button
              aria-expanded={confirmDeleteId === item.id}
              aria-haspopup="dialog"
              aria-label={t('savedSearches.deleteAria', {
                name: item.name,
              })}
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
            aria-labelledby={`saved-search-delete-title-${item.id}`}
            className="saved-search-delete-popover"
            collisionPadding={12}
            side="bottom"
            sideOffset={6}
          >
            <div className="saved-search-delete-popover-inner">
              <p
                className="saved-search-delete-popover-title"
                id={`saved-search-delete-title-${item.id}`}
              >
                {t('savedSearches.removeNamed', {
                  name: item.name,
                })}
              </p>
              <div className="saved-search-delete-popover-actions">
                <Popover.Close asChild>
                  <button
                    className="secondary saved-search-delete-cancel"
                    type="button"
                  >
                    {t('common.cancel')}
                  </button>
                </Popover.Close>
                <button
                  aria-describedby={`saved-search-delete-title-${item.id}`}
                  aria-label={t('savedSearches.deleteForeverAria', {
                    name: item.name,
                  })}
                  className="danger saved-search-delete-commit"
                  onClick={() => void commitDelete(item.id)}
                  type="button"
                >
                  {t('savedSearches.deleteTitle')}
                </button>
              </div>
            </div>
          </Popover.Content>
        </Popover.Portal>
      </Popover.Root>
    </div>
  );

  return (
    <section className="page saved-searches-page pagination-bar-scope">
      {error && <div className="error">{error}</div>}
      <div className="feature-page-stack">
        <div className="panel">
          <div className="panel-head saved-search-lib-head">
            <div className="saved-search-lib-head-meta">
              <h2>{t('savedSearches.library')}</h2>
              <p className="panel-subtitle">{t('savedSearches.subtitle')}</p>
            </div>
            <div className="saved-search-lib-head-tools">
              {filterText && (
                <span className="saved-search-result-meta">
                  {filtered.length} / {items.length}
                </span>
              )}
              <input
                autoComplete="off"
                className="saved-search-filter-input"
                onChange={(e) => setFilterText(e.target.value)}
                placeholder={t('savedSearches.filterPh')}
                type="search"
                value={filterText}
              />
              <button disabled={demoMode} onClick={() => setCreateOpen(true)} type="button">
                  <Plus aria-hidden size={16} />
                  {t('savedSearches.newSaved')}
              </button>
            </div>
          </div>
          {isMobile ? (
            <UvCardList
              empty={
                total === 0 ? (
                  <EmptyState
                    hint={t('emptyState.savedSearches.hint')}
                    icon={<BookmarkPlus size={28} />}
                    title={t('emptyState.savedSearches.title')}
                  />
                ) : (
                  <div className="saved-search-empty-filter">
                    {t('savedSearches.noFilterMatch', { q: filterText })}
                  </div>
                )
              }
              getRowId={(item) => item.id}
              loading={loading}
              renderCard={(item) => (
                <>
                  <div className="uv-card__head">
                    <span className="uv-card__title">{item.name}</span>
                  </div>
                  <div className="uv-card__body saved-search-card-filters match-cell">
                    {renderQueryTags(item.query, t)}
                  </div>
                  <div className="uv-card__meta saved-search-card-dates">
                    <span>{formatDate(item.created_at)}</span>
                    <span>{renderLastRun(item.last_run_at, t)}</span>
                  </div>
                  <div className="uv-card__actions">
                    {renderSavedSearchActions(item)}
                  </div>
                </>
              )}
              rows={filtered}
            />
          ) : (
          <div className="table-wrap pagination-scroll-anchor">
            <table>
              <thead>
                <tr>
                  <th>{t('columns.name')}</th>
                  <th>{t('columns.filters')}</th>
                  <th>{t('columns.created')}</th>
                  <th>{t('columns.lastRun')}</th>
                  <th>{t('columns.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {loading && items.length === 0 && skeletonRows}
                {!loading && total === 0 && (
                  <tr>
                    <td className="table-empty-cell" colSpan={5}>
                      <EmptyState
                        action={
                          <button
                            disabled={demoMode}
                            onClick={() => setCreateOpen(true)}
                            type="button"
                          >
                            <Plus aria-hidden size={16} />
                            {t('common.create')}
                          </button>
                        }
                        hint={t('emptyState.savedSearches.hint')}
                        icon={<BookmarkPlus size={28} />}
                        title={t('emptyState.savedSearches.title')}
                      />
                    </td>
                  </tr>
                )}
                {!loading && items.length > 0 && filtered.length === 0 && (
                  <tr>
                    <td className="table-empty-cell" colSpan={5}>
                      {t('savedSearches.noFilterMatch', { q: filterText })}
                    </td>
                  </tr>
                )}
                {filtered.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <strong>{item.name}</strong>
                    </td>
                    <td className="match-cell">
                      {renderQueryTags(item.query, t)}
                    </td>
                    <td>{formatDate(item.created_at)}</td>
                    <td>{renderLastRun(item.last_run_at, t)}</td>
                    <td className="saved-search-actions-cell">
                      {renderSavedSearchActions(item)}
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

      <Dialog.Root onOpenChange={setCreateOpen} open={createOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <DialogSheetContent
            className="saved-search-dialog"
            onDismiss={() => setCreateOpen(false)}
          >
            <Dialog.Title>{t('savedSearches.dialogCreateTitle')}</Dialog.Title>
            <Dialog.Description className="panel-subtitle">
              {t('savedSearches.dialogCreateDesc')}
            </Dialog.Description>
            <form onSubmit={handleCreate}>
              <div className="saved-form-section">
                <div className="saved-form-section-label">
                  {t('savedSearches.sectionBasic')}
                </div>
                <label className="search-field">
                  <span className="search-field-label">{t('alerts.name')}</span>
                  <input
                    autoFocus
                    onChange={(e) => setFormName(e.target.value)}
                    placeholder={t('savedSearches.namePh')}
                    required
                    value={formName}
                  />
                </label>
                <label className="search-field">
                  <span className="search-field-label">
                    {t('alerts.queryLabel')}
                  </span>
                  <input
                    onChange={(e) => setFormQ(e.target.value)}
                    placeholder={t('savedSearches.queryPh')}
                    value={formQ}
                  />
                </label>
              </div>
              <div className="saved-form-section">
                <div className="saved-form-section-label">
                  {t('savedSearches.sectionNetwork')}
                </div>
                <div className="search-filter-grid">
                  <label className="search-field">
                    <span className="search-field-label">
                      {t('searchPage.port')}
                    </span>
                    <input
                      onChange={(e) => setFormPort(e.target.value)}
                      placeholder={t('savedSearches.placeholderPort')}
                      type="number"
                      value={formPort}
                    />
                  </label>
                  <label className="search-field">
                    <span className="search-field-label">
                      {t('searchPage.country')}
                    </span>
                    <input
                      maxLength={2}
                      onChange={(e) => setFormCountry(e.target.value)}
                      placeholder={t('savedSearches.placeholderCountry')}
                      value={formCountry}
                    />
                  </label>
                  <label className="search-field">
                    <span className="search-field-label">
                      {t('searchPage.protocol')}
                    </span>
                    <input
                      onChange={(e) => setFormProtocol(e.target.value)}
                      placeholder={t('savedSearches.placeholderProtocol')}
                      value={formProtocol}
                    />
                  </label>
                  <label className="search-field">
                    <span className="search-field-label">
                      {t('searchPage.asn')}
                    </span>
                    <input
                      onChange={(e) => setFormASN(e.target.value)}
                      placeholder={t('savedSearches.placeholderAsn')}
                      value={formASN}
                    />
                  </label>
                </div>
              </div>
              <button
                className="ghost saved-search-advanced-toggle"
                onClick={() => setAdvancedOpen((v) => !v)}
                type="button"
              >
                {advancedOpen ? (
                  <ChevronUp aria-hidden size={14} />
                ) : (
                  <ChevronDown aria-hidden size={14} />
                )}
                {t('savedSearches.advancedFilters')}
              </button>
              {advancedOpen && (
                <div className="saved-form-section">
                  <div className="saved-form-section-label">
                    {t('savedSearches.sectionAdvanced')}
                  </div>
                  <div className="search-filter-grid search-filter-grid-advanced">
                    <label className="search-field">
                      <span className="search-field-label">
                        {t('savedSearches.hasCve')}
                      </span>
                      <Select
                        onChange={setFormHasCVE}
                        options={[
                          { value: '', label: t('savedSearches.anyOption') },
                          { value: 'true', label: t('savedSearches.yesOption') },
                        ]}
                        value={formHasCVE}
                      />
                    </label>
                    <label className="search-field">
                      <span className="search-field-label">
                        {t('savedSearches.cveSeverityLabel')}
                      </span>
                      <Select
                        onChange={setFormCVESeverity}
                        options={[
                          { value: '', label: t('savedSearches.anyOption') },
                          ...CVE_SEVERITIES.map((s) => ({
                            value: s,
                            label: s,
                          })),
                        ]}
                        value={formCVESeverity}
                      />
                    </label>
                    <label className="search-field search-field-wide">
                      <span className="search-field-label">
                        {t('searchPage.tlsIssuer')}
                      </span>
                      <input
                        onChange={(e) => setFormTLSIssuer(e.target.value)}
                        placeholder={t('searchPage.tlsIssuerPh')}
                        value={formTLSIssuer}
                      />
                    </label>
                    <label className="search-field search-field-wide">
                      <span className="search-field-label">
                        {t('searchPage.tlsFp')}
                      </span>
                      <input
                        onChange={(e) => setFormTLSFingerprint(e.target.value)}
                        placeholder={t('savedSearches.placeholderTlsFp')}
                        value={formTLSFingerprint}
                      />
                    </label>
                    <label className="search-field">
                      <span className="search-field-label">
                        {t('searchPage.riskMin')}
                      </span>
                      <input
                        max={100}
                        min={0}
                        onChange={(e) => setFormRiskMin(e.target.value)}
                        type="number"
                        value={formRiskMin}
                      />
                    </label>
                    <label className="search-field">
                      <span className="search-field-label">
                        {t('searchPage.riskMax')}
                      </span>
                      <input
                        max={100}
                        min={0}
                        onChange={(e) => setFormRiskMax(e.target.value)}
                        type="number"
                        value={formRiskMax}
                      />
                    </label>
                    <label className="search-field">
                      <span className="search-field-label">
                        {t('searchPage.lastSeenFrom')}
                      </span>
                      <input
                        onChange={(e) => setFormLastSeenFrom(e.target.value)}
                        type="date"
                        value={formLastSeenFrom}
                      />
                    </label>
                    <label className="search-field">
                      <span className="search-field-label">
                        {t('searchPage.lastSeenTo')}
                      </span>
                      <input
                        onChange={(e) => setFormLastSeenTo(e.target.value)}
                        type="date"
                        value={formLastSeenTo}
                      />
                    </label>
                  </div>
                </div>
              )}
              <div className="dialog-actions">
                <Dialog.Close asChild>
                  <button className="secondary" type="button">
                    <X aria-hidden size={16} />
                    {t('common.cancel')}
                  </button>
                </Dialog.Close>
                <button disabled={demoMode} type="submit">
                  <Plus aria-hidden size={16} />
                  {t('savedSearches.saveSearch')}
                </button>
              </div>
            </form>
          </DialogSheetContent>
        </Dialog.Portal>
      </Dialog.Root>
    </section>
  );
}
