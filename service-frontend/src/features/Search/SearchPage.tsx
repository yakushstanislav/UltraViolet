import { ChevronDown, ChevronUp, Download, Search } from 'lucide-react';
import {
  type ClipboardEvent,
  type FormEvent,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { CopyButton } from '@components/CopyButton';
import { PaginationBarDock } from '@components/PaginationBarDock';
import { EmptyState } from '@components/EmptyState';
import { HostHoverCard } from '@components/HostHoverCard';
import { InlineError } from '@components/InlineError';
import { Select } from '@components/Select';
import { SkeletonRow } from '@components/Skeleton';
import { Tooltip } from '@components/Tooltip';
import { UvCardList } from '@components/UvCardList';
import { useIsMobile } from '@/hooks/useBreakpoint';
import { showActionError, showActionSuccess } from '@helpers/uiError';
import {
  readRecentSearchQueries,
  rememberSearchQuery,
} from '@helpers/recentSearchQueries';
import { useTableKeyboardNav } from '@/hooks/useTableKeyboardNav';

import { buildSearchParamsFromForm, searchPermalinkFromParams } from './buildSearchParams';
import { SearchCountriesGlobe } from './SearchCountriesGlobe';
import { SearchDatePicker } from './SearchDatePicker';
import { SearchLastSeenPresets } from './SearchLastSeenPresets';
import { runSearch } from './searchActions';
import { resetSearch } from './searchSlice';
import { SearchableCountrySelect } from './SearchableCountrySelect';
import { countryCodeToFlagEmoji } from '@helpers/countryFlagEmoji';
import { cveSeverityLabel } from '@helpers/cveSeverity';
import { scrollPaginationAnchor } from '@helpers/scrollPaginationAnchor';
import { parsePositiveInt } from '@helpers/searchParams';
import { useAppDispatch, useAppSelector } from '@store/store';

import { ProtocolSelect } from './ProtocolSelect';
import { exportSearchCsv } from './exportSearchCsv';
import {
  ADVANCED_FILTER_KEYS,
  CVE_SEVERITIES,
  Q_MODE_FUZZY,
  SEARCH_FIELD_KEYS,
  formatSearchChipValue,
  optionalSearchParam,
  parseSearchPromote,
  parseSearchQMode,
  rfc3339ToDateInput,
  searchFieldPlaceholderKey,
  searchFieldTranslationKey,
  type SearchFieldKey,
} from './searchFormHelpers';

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 25;

// URL-driven search params bypass the form's zod validation, so they need a
// second guard before being threaded into the API call. NaN or non-RFC3339
// inputs from a hand-edited query string would otherwise be serialised
// verbatim and fail server-side.
function parseConfidenceGTE(raw: string): number | undefined {
  if (raw === '') {
    return undefined;
  }

  const value = Number(raw);

  return Number.isFinite(value) ? value : undefined;
}

export function SearchPage() {
  const { t } = useTranslation();
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const { hits, loading, error, total } = useAppSelector(
    (state) => state.search
  );
  const [params, setParams] = useSearchParams();
  const [advancedOpen, setAdvancedOpen] = useState(() =>
    ADVANCED_FILTER_KEYS.some((k) => params.get(k))
  );
  const [mobileFiltersOpen, setMobileFiltersOpen] = useState(false);
  const [recentQueries, setRecentQueries] = useState<string[]>(() =>
    readRecentSearchQueries()
  );
  const currentQ = params.get('q') ?? '';
  const currentQMode = params.get('q_mode') ?? '';
  const currentPort = params.get('port') ?? '';
  const currentPortFrom = params.get('port_from') ?? '';
  const currentPortTo = params.get('port_to') ?? '';
  const currentCountry = params.get('country') ?? '';
  const currentASN = params.get('asn') ?? '';
  const currentProtocol = params.get('protocol') ?? '';
  const currentTLSIssuer = params.get('tls_issuer') ?? '';
  const currentTLSFingerprint = params.get('tls_fingerprint') ?? '';
  const currentTLSSubject = params.get('tls_subject') ?? '';
  const currentTLSSAN = params.get('tls_san') ?? '';
  const currentSSH = params.get('ssh') ?? '';
  const currentSSHFingerprint = params.get('ssh_fingerprint') ?? '';
  const currentSMTP = params.get('smtp') ?? '';
  const currentDNS = params.get('dns') ?? '';
  const currentCVEID = params.get('cve_id') ?? '';
  const currentCVEText = params.get('cve_text') ?? '';
  const currentSort = params.get('sort') ?? '';
  const currentRiskScoreMin = params.get('risk_score_min') ?? '';
  const currentRiskScoreMax = params.get('risk_score_max') ?? '';
  const currentLastSeenFrom = params.get('last_seen_from') ?? '';
  const currentLastSeenTo = params.get('last_seen_to') ?? '';
  const currentCVESeverity = params.get('cve_severity') ?? '';
  const currentConfidenceGTE = params.get('confidence_gte') ?? '';
  const currentCVESeverityList = useMemo(
    () =>
      currentCVESeverity
        .split(',')
        .map((s) => s.trim().toUpperCase())
        .filter((s) => s !== ''),
    [currentCVESeverity]
  );
  const currentPage = parsePositiveInt(params.get('page'), DEFAULT_PAGE);
  const currentLimit = parsePositiveInt(params.get('limit'), DEFAULT_LIMIT);
  const totalPages = Math.max(1, Math.ceil(total / currentLimit));
  const activeAdvancedCount = ADVANCED_FILTER_KEYS.filter((k) =>
    params.get(k)
  ).length;
  const isPresetActive = (preset: Partial<Record<SearchFieldKey, string>>) =>
    Object.entries(preset).every(
      ([k, v]) => (params.get(k) ?? '') === (v ?? '')
    );
  const activeFilters = useMemo(
    () =>
      SEARCH_FIELD_KEYS.map((key) => ({
        key,
        value: params.get(key) ?? '',
      })).filter((item) => item.value !== ''),
    [params]
  );

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const form = new FormData(event.currentTarget);
    const nextParams = buildSearchParamsFromForm(form, {
      sort: currentSort || undefined,
      page: DEFAULT_PAGE,
      limit: currentLimit,
    });

    const submittedQ = (form.get('q') ?? '').toString().trim();
    if (submittedQ !== '') {
      rememberSearchQuery(submittedQ);
      setRecentQueries(readRecentSearchQueries());
    }

    setMobileFiltersOpen(false);

    if (nextParams.toString() === params.toString()) {
      void dispatch(runSearch(runSearchParams));

      return;
    }

    setParams(nextParams);
  };

  const handleQueryPaste = (event: ClipboardEvent<HTMLInputElement>) => {
    const text = event.clipboardData.getData('text');
    const promote = parseSearchPromote(text);
    if (!promote) {
      return;
    }

    event.preventDefault();

    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set(promote.key, promote.value);
      next.set('page', '1');
      return next;
    });

    if (ADVANCED_FILTER_KEYS.some((k) => k === promote.key)) {
      setAdvancedOpen(true);
    }

    showActionSuccess('searchPage.promoteToast', {
      key: t(searchFieldTranslationKey(promote.key)),
    });
  };

  const applyLastSeenRange = (from: string, to: string) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('last_seen_from', from);
      next.set('last_seen_to', to);
      next.set('page', '1');
      return next;
    });
    setAdvancedOpen(true);
  };

  const handleExportCSV = () => {
    void exportSearchCsv(params, (err) => {
      if (err.kind === 'failed') {
        showActionError(err.cause, 'searchPage.exportFailed');
      }
    });
  };

  const applyPreset = (partial: Partial<Record<SearchFieldKey, string>>) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      Object.entries(partial).forEach(([key, value]) => {
        if (!value) {
          next.delete(key);
          return;
        }
        next.set(key, value);
      });
      return next;
    });
  };

  const clearFilters = () => {
    setParams({ page: '1', limit: String(currentLimit) });
    setAdvancedOpen(false);
  };

  const handleSortChange = (value: string) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value) {
        next.set('sort', value);
      } else {
        next.delete('sort');
      }
      next.set('page', '1');
      return next;
    });
  };

  const removeFilter = (key: SearchFieldKey) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete(key);
      next.set('page', '1');
      return next;
    });
  };

  const searchKey = params.toString();

  const runSearchParams = useMemo(
    () => ({
      q: optionalSearchParam(currentQ),
      q_mode: parseSearchQMode(currentQMode),
      port: optionalSearchParam(currentPort),
      port_from: currentPortFrom ? Number(currentPortFrom) : undefined,
      port_to: currentPortTo ? Number(currentPortTo) : undefined,
      country: optionalSearchParam(currentCountry),
      asn: optionalSearchParam(currentASN),
      protocol: optionalSearchParam(currentProtocol),
      tls_issuer: optionalSearchParam(currentTLSIssuer),
      tls_fingerprint: optionalSearchParam(currentTLSFingerprint),
      tls_subject: optionalSearchParam(currentTLSSubject),
      tls_san: optionalSearchParam(currentTLSSAN),
      ssh: optionalSearchParam(currentSSH),
      ssh_fingerprint: optionalSearchParam(currentSSHFingerprint),
      smtp: optionalSearchParam(currentSMTP),
      dns: optionalSearchParam(currentDNS),
      cve_id: optionalSearchParam(currentCVEID),
      cve_text: optionalSearchParam(currentCVEText),
      sort: optionalSearchParam(currentSort),
      risk_score_min: currentRiskScoreMin
        ? Number(currentRiskScoreMin)
        : undefined,
      risk_score_max: currentRiskScoreMax
        ? Number(currentRiskScoreMax)
        : undefined,
      last_seen_from: currentLastSeenFrom || undefined,
      last_seen_to: currentLastSeenTo || undefined,
      has_cve: currentCVESeverity ? 'true' : undefined,
      cve_severity: currentCVESeverity || undefined,
      confidence_gte: parseConfidenceGTE(currentConfidenceGTE),
      page: currentPage,
      limit: currentLimit,
    }),
    // searchKey captures every URL param; rebuilding only when the URL changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [searchKey]
  );

  useEffect(() => {
    const promise = dispatch(runSearch(runSearchParams));

    return () => {
      promise.abort();
    };
  }, [dispatch, runSearchParams]);

  const isMobile = useIsMobile();
  const hitIds = useMemo(() => hits.map((hit) => hit.service_id), [hits]);
  const { activeId: activeHitId } = useTableKeyboardNav<number>({
    rowIds: hitIds,
    onActivate: (id) => {
      const hit = hits.find((h) => h.service_id === id);
      if (hit) {
        navigate(`/hosts/${encodeURIComponent(hit.ip)}`);
      }
    },
  });

  useEffect(() => {
    return () => {
      dispatch(resetSearch());
    };
  }, [dispatch]);

  return (
    <section className="page search-page">
      <div className="search-layout">
        {mobileFiltersOpen && (
          <button
            aria-label={t('common.close')}
            className="search-mobile-backdrop mobile-nav-backdrop"
            onClick={() => setMobileFiltersOpen(false)}
            type="button"
          />
        )}
        <aside
          className={`panel search-sidebar ${mobileFiltersOpen ? 'open' : ''}`}
        >
          <div className="search-sidebar-head">
            <div className="search-sidebar-title">
              <h2>{t('searchPage.filters')}</h2>
              {activeFilters.length > 0 && (
                <span className="search-filters-count">
                  {activeFilters.length}
                </span>
              )}
            </div>
            <button
              className="secondary search-mobile-close"
              onClick={() => setMobileFiltersOpen(false)}
              type="button"
            >
              {t('common.close')}
            </button>
          </div>
          <form
            className="stack-form search-form"
            id="search-form"
            onSubmit={submit}
          >
            <div className="search-sticky-actions">
              <button type="submit">{t('common.search')}</button>
              <button
                className="secondary"
                onClick={clearFilters}
                type="button"
              >
                {t('common.reset')}
              </button>
            </div>
            <div>
              <div className="filter-group-title">
                {t('searchPage.coreFilters')}
              </div>
              <div className="search-filter-grid">
                <label className="search-field search-field-wide">
                  <span className="search-field-label">
                    {t('searchPage.queryTitle')}
                  </span>
                  <input
                    defaultValue={currentQ}
                    key={`q-${currentQ}`}
                    list="uv-recent-queries"
                    name="q"
                    onPaste={handleQueryPaste}
                    placeholder={t('searchPage.queryPh')}
                    title={t('searchPage.queryTitleAttr')}
                  />
                  {recentQueries.length > 0 && (
                    <datalist id="uv-recent-queries">
                      {recentQueries.map((q) => (
                        <option key={q} value={q} />
                      ))}
                    </datalist>
                  )}
                </label>
                <label
                  className="search-fuzzy-option search-field-wide"
                  title={t('searchPage.fuzzyMatchHint')}
                >
                  <input
                    defaultChecked={currentQMode === Q_MODE_FUZZY}
                    key={`q-mode-${currentQMode}`}
                    name="q_mode"
                    type="checkbox"
                    value="on"
                  />
                  <span>{t(searchFieldTranslationKey('q_mode'))}</span>
                </label>
                <label className="search-field">
                  <span className="search-field-label">
                    {t('searchPage.port')}
                  </span>
                  <input
                    defaultValue={currentPort}
                    key={`port-${currentPort}`}
                    max="65535"
                    min="1"
                    name="port"
                    placeholder={t('searchPage.portPh')}
                    type="number"
                  />
                </label>
                <div className="search-field">
                  <span className="search-field-label">
                    {t('searchPage.country')}
                  </span>
                  <SearchableCountrySelect
                    name="country"
                    value={currentCountry}
                  />
                </div>
                <label className="search-field search-field-wide">
                  <span className="search-field-label">
                    <Tooltip label={t('terms.asn')}>
                      <abbr className="uv-term-abbr">
                        {t('searchPage.asn')}
                      </abbr>
                    </Tooltip>
                  </span>
                  <input
                    defaultValue={currentASN}
                    key={`asn-${currentASN}`}
                    min="1"
                    name="asn"
                    placeholder={t('searchPage.asnPh')}
                    type="number"
                  />
                </label>
              </div>
            </div>
            <div>
              <button
                className="secondary search-advanced-toggle"
                onClick={() => setAdvancedOpen((value) => !value)}
                type="button"
              >
                {advancedOpen ? (
                  <ChevronUp aria-hidden size={14} />
                ) : (
                  <ChevronDown aria-hidden size={14} />
                )}
                {t('searchPage.advancedToggle')}
                {!advancedOpen && activeAdvancedCount > 0 && (
                  <span className="search-advanced-badge">
                    {activeAdvancedCount}
                  </span>
                )}
              </button>
              {advancedOpen && (
                <div className="search-filter-grid search-filter-grid-advanced">
                  <div className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t('searchPage.protocol')}
                    </span>
                    <ProtocolSelect
                      defaultValue={currentProtocol}
                      name="protocol"
                    />
                  </div>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t('searchPage.tlsIssuer')}
                    </span>
                    <input
                      defaultValue={currentTLSIssuer}
                      key={`tls-issuer-${currentTLSIssuer}`}
                      name="tls_issuer"
                      placeholder={t('searchPage.tlsIssuerPh')}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t('searchPage.tlsFp')}
                    </span>
                    <input
                      defaultValue={currentTLSFingerprint}
                      key={`tls-fp-${currentTLSFingerprint}`}
                      name="tls_fingerprint"
                      placeholder={t('searchPage.tlsFpPh')}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('tls_subject'))}
                    </span>
                    <input
                      defaultValue={currentTLSSubject}
                      key={`tls-subject-${currentTLSSubject}`}
                      name="tls_subject"
                      placeholder={t(searchFieldPlaceholderKey('tls_subject'))}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('tls_san'))}
                    </span>
                    <input
                      defaultValue={currentTLSSAN}
                      key={`tls-san-${currentTLSSAN}`}
                      name="tls_san"
                      placeholder={t(searchFieldPlaceholderKey('tls_san'))}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('ssh'))}
                    </span>
                    <input
                      defaultValue={currentSSH}
                      key={`ssh-${currentSSH}`}
                      name="ssh"
                      placeholder={t(searchFieldPlaceholderKey('ssh'))}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('ssh_fingerprint'))}
                    </span>
                    <input
                      defaultValue={currentSSHFingerprint}
                      key={`ssh-fp-${currentSSHFingerprint}`}
                      name="ssh_fingerprint"
                      placeholder={t(
                        searchFieldPlaceholderKey('ssh_fingerprint')
                      )}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('smtp'))}
                    </span>
                    <input
                      defaultValue={currentSMTP}
                      key={`smtp-${currentSMTP}`}
                      name="smtp"
                      placeholder={t(searchFieldPlaceholderKey('smtp'))}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('dns'))}
                    </span>
                    <input
                      defaultValue={currentDNS}
                      key={`dns-${currentDNS}`}
                      name="dns"
                      placeholder={t(searchFieldPlaceholderKey('dns'))}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('cve_id'))}
                    </span>
                    <input
                      defaultValue={currentCVEID}
                      key={`cve-id-${currentCVEID}`}
                      name="cve_id"
                      placeholder={t(searchFieldPlaceholderKey('cve_id'))}
                    />
                  </label>
                  <label className="search-field search-field-wide">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('cve_text'))}
                    </span>
                    <input
                      defaultValue={currentCVEText}
                      key={`cve-text-${currentCVEText}`}
                      name="cve_text"
                      placeholder={t(searchFieldPlaceholderKey('cve_text'))}
                    />
                  </label>
                  <label className="search-field">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('risk_score_min'))}
                    </span>
                    <input
                      defaultValue={currentRiskScoreMin}
                      key={`risk-min-${currentRiskScoreMin}`}
                      max="100"
                      min="0"
                      name="risk_score_min"
                      placeholder={t('searchPage.riskMinPh')}
                      type="number"
                    />
                  </label>
                  <label className="search-field">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('risk_score_max'))}
                    </span>
                    <input
                      defaultValue={currentRiskScoreMax}
                      key={`risk-max-${currentRiskScoreMax}`}
                      max="100"
                      min="0"
                      name="risk_score_max"
                      placeholder={t('searchPage.riskMaxPh')}
                      type="number"
                    />
                  </label>
                  <label className="search-field">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('port_from'))}
                    </span>
                    <input
                      defaultValue={currentPortFrom}
                      key={`port-from-${currentPortFrom}`}
                      max="65535"
                      min="1"
                      name="port_from"
                      placeholder={t('searchPage.portFromPh')}
                      type="number"
                    />
                  </label>
                  <label className="search-field">
                    <span className="search-field-label">
                      {t(searchFieldTranslationKey('port_to'))}
                    </span>
                    <input
                      defaultValue={currentPortTo}
                      key={`port-to-${currentPortTo}`}
                      max="65535"
                      min="1"
                      name="port_to"
                      placeholder={t('searchPage.portToPh')}
                      type="number"
                    />
                  </label>
                  <div className="search-field search-field-wide search-last-seen-block">
                    <SearchLastSeenPresets onApply={applyLastSeenRange} />
                    <label className="search-field">
                      <span className="search-field-label">
                        {t(searchFieldTranslationKey('last_seen_from'))}
                      </span>
                      <SearchDatePicker
                        isoDate={rfc3339ToDateInput(currentLastSeenFrom)}
                        key={`seen-from-${currentLastSeenFrom}`}
                        name="last_seen_from"
                      />
                    </label>
                    <label className="search-field">
                      <span className="search-field-label">
                        {t(searchFieldTranslationKey('last_seen_to'))}
                      </span>
                      <SearchDatePicker
                        isoDate={rfc3339ToDateInput(currentLastSeenTo)}
                        key={`seen-to-${currentLastSeenTo}`}
                        name="last_seen_to"
                      />
                    </label>
                  </div>
                  <div className="search-field search-field-wide">
                    <span className="search-field-label">
                      <Tooltip label={t('terms.cveSeverity')}>
                        <abbr className="uv-term-abbr">
                          {t('searchPage.cveSeverity')}
                        </abbr>
                      </Tooltip>
                    </span>
                    <div className="search-cve-severity-options">
                      {CVE_SEVERITIES.map((sev) => (
                        <label className="search-cve-severity-option" key={sev}>
                          <input
                            defaultChecked={currentCVESeverityList.includes(
                              sev
                            )}
                            key={`cve-sev-${sev}-${currentCVESeverity}`}
                            name="cve_severity"
                            type="checkbox"
                            value={sev}
                          />
                          <span
                            className={`cve-severity cve-severity-${sev.toLowerCase()}`}
                          >
                            {cveSeverityLabel(sev, t)}
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                  <label className="search-field">
                    <span className="search-field-label">
                      {t('risk.search.confidenceGte')}
                    </span>
                    <input
                      defaultValue={currentConfidenceGTE}
                      key={`conf-${currentConfidenceGTE}`}
                      max="1"
                      min="0"
                      name="confidence_gte"
                      placeholder="0.7"
                      step="0.05"
                      type="number"
                    />
                  </label>
                </div>
              )}
            </div>
            <div>
              <div className="filter-group-title">
                {t('searchPage.quickPresets')}
              </div>
              <div className="search-presets">
                <button
                  className={isPresetActive({ port: '443' }) ? '' : 'secondary'}
                  onClick={() => applyPreset({ port: '443' })}
                  type="button"
                >
                  {t('searchPage.presetHttps443')}
                </button>
                <button
                  className={
                    isPresetActive({ protocol: 'http', port: '' })
                      ? ''
                      : 'secondary'
                  }
                  onClick={() => applyPreset({ protocol: 'http', port: '' })}
                  type="button"
                >
                  {t('searchPage.presetHttpOnly')}
                </button>
                <button
                  className={
                    isPresetActive({ protocol: 'https', port: '' })
                      ? ''
                      : 'secondary'
                  }
                  onClick={() => applyPreset({ protocol: 'https', port: '' })}
                  type="button"
                >
                  {t('searchPage.presetHttpsOnly')}
                </button>
                <button
                  className={
                    isPresetActive({ risk_score_min: '70' }) ? '' : 'secondary'
                  }
                  onClick={() => {
                    applyPreset({ risk_score_min: '70' });
                    setAdvancedOpen(true);
                  }}
                  type="button"
                >
                  {t('searchPage.presetHighRisk')}
                </button>
                <button
                  className={isPresetActive({ port: '80' }) ? '' : 'secondary'}
                  onClick={() => applyPreset({ port: '80' })}
                  type="button"
                >
                  {t('searchPage.presetPort80')}
                </button>
                <button
                  className={
                    isPresetActive({ port: '8080' }) ? '' : 'secondary'
                  }
                  onClick={() => applyPreset({ port: '8080' })}
                  type="button"
                >
                  {t('searchPage.presetPort8080')}
                </button>
              </div>
            </div>
          </form>
          <SearchCountriesGlobe
            filterCountryCode={currentCountry}
            hits={hits}
          />
        </aside>
        <div className="search-results pagination-bar-scope">
          <div className="panel search-results-head">
            <div className="search-results-head-top">
              <div className="search-results-actions">
                <button
                  className="secondary search-mobile-filters"
                  onClick={() => setMobileFiltersOpen(true)}
                  type="button"
                >
                  {t('searchPage.filters')}
                </button>
                <CopyButton
                  className="secondary"
                  copiedLabel={t('searchPage.shareLinkCopied')}
                  label={t('searchPage.shareLink')}
                  text={searchPermalinkFromParams(params)}
                />
                <button
                  className="secondary"
                  disabled={loading || total === 0}
                  onClick={handleExportCSV}
                  title={t('searchPage.exportCsvTitle')}
                  type="button"
                >
                  <Download aria-hidden size={14} />
                  {t('searchPage.exportCsv')}
                </button>
              </div>
            </div>
            {activeFilters.length > 0 && (
              <div className="search-active-filters search-active-filters--results">
                {activeFilters.map((item) => (
                  <button
                    aria-label={t('searchPage.removeFilterAria', {
                      label: t(searchFieldTranslationKey(item.key)),
                    })}
                    className="search-filter-chip"
                    key={item.key}
                    onClick={() => removeFilter(item.key)}
                    type="button"
                  >
                    <span className="search-filter-chip-key">
                      {t(searchFieldTranslationKey(item.key))}
                    </span>
                    <span
                      className="search-filter-chip-value"
                      title={item.value}
                    >
                      {formatSearchChipValue(item.key, item.value, t)}
                    </span>
                    <span aria-hidden className="search-filter-chip-x">
                      ×
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
          {error && (
            <InlineError
              message={error}
              onRetry={() => {
                void dispatch(runSearch(runSearchParams));
              }}
            />
          )}
          <div className="table-wrap search-table-wrap pagination-scroll-anchor">
            {isMobile ? (
              <UvCardList
                activeId={activeHitId}
                empty={
                  <EmptyState
                    action={
                      activeFilters.length > 0 ? (
                        <button
                          className="secondary"
                          onClick={clearFilters}
                          type="button"
                        >
                          {t('emptyState.search.clearFilters')}
                        </button>
                      ) : undefined
                    }
                    hint={
                      activeFilters.length > 0
                        ? t('searchPage.noResultsHint')
                        : undefined
                    }
                    icon={<Search size={28} />}
                    title={
                      activeFilters.length > 0
                        ? t('emptyState.search.noResults')
                        : t('searchPage.noResultsTitle')
                    }
                  />
                }
                getRowId={(hit) => hit.service_id}
                loading={loading}
                onRowActivate={(hit) =>
                  navigate(`/hosts/${encodeURIComponent(hit.ip)}`)
                }
                renderCard={(hit) => (
                  <>
                    <div className="uv-card__head">
                      <span className="uv-card__title cell-mono">
                        <HostHoverCard ip={hit.ip}>{hit.ip}</HostHoverCard>
                      </span>
                      {hit.country_code ? (
                        <span
                          aria-hidden
                          className="search-geo-flag-emoji"
                          title={hit.country_code}
                        >
                          {countryCodeToFlagEmoji(hit.country_code)}
                        </span>
                      ) : null}
                    </div>
                    <div className="uv-card__meta">
                      <span className="cell-mono">
                        {t('columns.port')}: {hit.port}
                      </span>
                      <span>{hit.protocol ?? hit.transport}</span>
                      <span>
                        {t('columns.risk')}: {hit.risk_score ?? 0}
                      </span>
                      {(hit.country_code || hit.asn) && (
                        <span>
                          {[hit.country_code, hit.asn ? `AS${hit.asn}` : '']
                            .filter(Boolean)
                            .join(' / ')}
                        </span>
                      )}
                    </div>
                    {(hit.status_code || hit.server || hit.title) && (
                      <div className="uv-card__body">
                        <span>
                          {[hit.status_code, hit.server, hit.title]
                            .filter(Boolean)
                            .join(' / ')}
                        </span>
                      </div>
                    )}
                  </>
                )}
                rows={hits}
              />
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t('columns.host')}</th>
                    <th>{t('columns.port')}</th>
                    <th>{t('columns.protocol')}</th>
                    <th>{t('columns.risk')}</th>
                    <th>{t('columns.geo')}</th>
                    <th>{t('columns.http')}</th>
                  </tr>
                </thead>
                <tbody>
                  {loading &&
                    hits.length === 0 &&
                    Array.from({ length: 6 }, (_, idx) => (
                      <SkeletonRow
                        cells={[
                          'short',
                          'short',
                          'mid',
                          'short',
                          'mid',
                          'long',
                        ]}
                        key={`sk-${idx}`}
                      />
                    ))}
                  {hits.map((hit) => {
                    const isActive = activeHitId === hit.service_id;
                    return (
                      <tr
                        className={isActive ? 'row-active' : undefined}
                        key={hit.service_id}
                      >
                        <td className="cell-mono">
                          <HostHoverCard ip={hit.ip}>
                            <Link to={`/hosts/${encodeURIComponent(hit.ip)}`}>
                              {hit.ip}
                            </Link>
                          </HostHoverCard>
                        </td>
                        <td className="cell-mono cell-numeric">{hit.port}</td>
                        <td>{hit.protocol ?? hit.transport}</td>
                        <td className="cell-numeric">{hit.risk_score ?? 0}</td>
                        <td>
                          <span className="search-geo-cell">
                            {hit.country_code ? (
                              <span
                                aria-hidden
                                className="search-geo-flag-emoji"
                                title={hit.country_code}
                              >
                                {countryCodeToFlagEmoji(hit.country_code)}
                              </span>
                            ) : null}
                            <span>
                              {[
                                hit.country_code,
                                hit.asn ? `AS${hit.asn}` : '',
                              ]
                                .filter(Boolean)
                                .join(' / ')}
                            </span>
                          </span>
                        </td>
                        <td>
                          {[hit.status_code, hit.server, hit.title]
                            .filter(Boolean)
                            .join(' / ')}
                        </td>
                      </tr>
                    );
                  })}
                  {!loading && hits.length === 0 && (
                    <tr>
                      <td className="table-empty-cell" colSpan={6}>
                        <EmptyState
                          action={
                            activeFilters.length > 0 ? (
                              <button
                                className="secondary"
                                onClick={clearFilters}
                                type="button"
                              >
                                {t('emptyState.search.clearFilters')}
                              </button>
                            ) : undefined
                          }
                          hint={
                            activeFilters.length > 0
                              ? t('searchPage.noResultsHint')
                              : undefined
                          }
                          icon={<Search size={28} />}
                          title={
                            activeFilters.length > 0
                              ? t('emptyState.search.noResults')
                              : t('searchPage.noResultsTitle')
                          }
                        />
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
          <PaginationBarDock>
          <div className="panel pagination-bar pagination-bar--with-sorts">
            <span className="pagination-bar-meta">
              {t('searchPage.paginationComma', {
                page: currentPage,
                pages: totalPages,
                total,
              })}
            </span>
            <div className="segmented-control pagination-bar-sorts" role="group">
              {(
                [
                  { value: '', labelKey: 'searchPage.sortLatest' },
                  { value: 'last_seen', labelKey: 'searchPage.sortLastSeen' },
                  { value: 'risk_score', labelKey: 'searchPage.sortRiskShort' },
                  { value: 'relevance', labelKey: 'searchPage.sortRelevance' },
                  { value: 'cvss_score', labelKey: 'searchPage.sortCvss' },
                ] as const
              ).map(({ value, labelKey }) => (
                <button
                  className={
                    currentSort === value
                      ? 'secondary segmented-active'
                      : 'secondary'
                  }
                  key={value}
                  onClick={() => handleSortChange(value)}
                  type="button"
                >
                  {t(labelKey)}
                </button>
              ))}
            </div>
            <div className="header-actions pagination-bar-controls">
              <label className="muted-text pagination-bar-limit">
                {t('searchPage.limit')}:
                <Select
                  compact
                  name="limit"
                  onChange={(next) => {
                    const limit = parsePositiveInt(next, 25);
                    setParams((prev) => {
                      const params = new URLSearchParams(prev);
                      params.set('page', '1');
                      params.set('limit', String(limit));
                      return params;
                    });
                  }}
                  options={[25, 50, 100].map((value) => ({
                    label: String(value),
                    value: String(value),
                  }))}
                  value={String(currentLimit)}
                />
              </label>
              <div className="pagination-bar-nav">
              <button
                className="secondary"
                disabled={currentPage <= 1 || loading}
                onClick={() => {
                  setParams((prev) => {
                    const next = new URLSearchParams(prev);
                    next.set('page', String(currentPage - 1));
                    return next;
                  });
                }}
                type="button"
              >
                {t('common.prev')}
              </button>
              <button
                className="secondary"
                disabled={currentPage >= totalPages || loading}
                onClick={() => {
                  setParams((prev) => {
                    const next = new URLSearchParams(prev);
                    next.set('page', String(currentPage + 1));
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
      </div>
    </section>
  );
}
