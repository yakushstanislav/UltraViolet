import { ChevronDown } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useSearchParams } from 'react-router-dom';

import { MobileTabs } from '@components/MobileTabs';
import { Select } from '@components/Select';
import { useIsPhablet } from '@/hooks/useBreakpoint';
import { formatDate } from '@helpers/format';
import { scrollPaginationAnchor } from '@helpers/scrollPaginationAnchor';
import { parsePositiveInt } from '@helpers/searchParams';
import { showActionError } from '@helpers/uiError';
import { getRelatedHosts } from '@services/RelatedHostsAPI';
import { useAppDispatch, useAppSelector } from '@store/store';
import type { RelatedHost } from '@/types/hosts';
import { HostDeepScanButton } from './HostDeepScanButton';
import { HostDnsTable } from './HostDnsTable';
import { loadHost } from './hostActions';
import { LazyHostLocationMap } from '@components/maps/LazyHostLocationMap';
import { PivotLink } from '@features/Pivot/PivotLink';
import {
  BODY_PREVIEW_CHARS,
  cveCountTotal,
  cveSeverityClass,
  hasServiceDetails,
  riskLabel,
  riskScoreClass,
  tlsExpiryClass,
} from './hostRiskHelpers';
import {
  defaultOnvifScheme,
  hostServiceEligibleForOnvif,
} from './hostServiceHelpers';
import { resetHost } from './hostSlice';
import { OnvifCommandBlock } from './OnvifCommandBlock';
import { CopyButton } from '@components/CopyButton';
import { PaginationBarDock } from '@components/PaginationBarDock';
import { rememberRecentHost } from '@components/commandPalette/recentHosts';
import { HostHttpOpenControl } from './HostHttpOpenControl';
import { HttpScreenshotBlock } from './HttpScreenshotBlock';
import { HttpSecurityInfoBlock } from './HttpSecurityInfoBlock';
import { RelatedHostsTable } from './RelatedHostsTable';
import { RtspSnapshotBlock, type RtspPathCue } from './RtspSnapshotBlock';
import { TlsFindingsBlock } from './TlsFindingsBlock';
import { TlsGradeBadge } from './TlsGradeBadge';
import { HostRecommendationsPanel } from './HostRecommendationsPanel';
import { HostRiskHistoryChart } from './HostRiskHistoryChart';
import { HostRiskPanel } from './HostRiskPanel';
import { ServiceExplainDisclosure } from './ServiceExplainDisclosure';

export function HostPage() {
  const { t } = useTranslation();
  const { ip = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const dispatch = useAppDispatch();
  const { data, loading, error } = useAppSelector((state) => state.host);
  const currentPage = parsePositiveInt(params.get('page'), 1);
  const currentLimit = parsePositiveInt(params.get('limit'), 25);
  const [serviceFilter, setServiceFilter] = useState<
    'all' | 'http' | 'tls' | 'high-risk'
  >('all');
  const [searchValue, setSearchValue] = useState('');
  const [expandedBodies, setExpandedBodies] = useState<Record<number, boolean>>(
    {}
  );
  const [related, setRelated] = useState<RelatedHost[]>([]);
  const [relatedLoading, setRelatedLoading] = useState(false);
  const [relatedPage, setRelatedPage] = useState(1);
  const [relatedTotal, setRelatedTotal] = useState(0);
  const relatedLimit = 10;
  const isPhablet = useIsPhablet();
  const [mobileSection, setMobileSection] = useState<
    'overview' | 'services' | 'related'
  >('overview');
  const [rtspPathCue, setRtspPathCue] = useState<{
    port: number;
    path: string;
    nonce: number;
  } | null>(null);

  useEffect(() => {
    if (ip !== '') {
      void dispatch(loadHost({ ip, page: currentPage, limit: currentLimit }));
    }
  }, [currentLimit, currentPage, dispatch, ip]);

  useEffect(() => {
    setRelatedPage(1);
  }, [ip]);

  useEffect(() => {
    if (ip === '') {
      return;
    }

    const controller = new AbortController();

    setRelated([]);
    setRelatedLoading(true);

    void getRelatedHosts(ip, relatedPage, relatedLimit, controller.signal)
      .then((response) => {
        if (controller.signal.aborted) {
          return;
        }

        setRelated(response.items ?? []);
        setRelatedTotal(response.total ?? 0);
        setRelatedLoading(false);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        setRelated([]);
        setRelatedTotal(0);
        setRelatedLoading(false);
        showActionError(err, 'common.loadFailed');
      });

    return () => {
      controller.abort();
    };
  }, [ip, relatedPage, relatedLimit]);

  useEffect(() => {
    return () => {
      dispatch(resetHost());
    };
  }, [dispatch]);

  useEffect(() => {
    if (data?.ip) {
      rememberRecentHost(data.ip);
    }
  }, [data?.ip]);

  const services = useMemo(() => {
    const query = searchValue.trim().toLowerCase();
    const filtered = (data?.services ?? []).filter((service) => {
      if (serviceFilter === 'http' && !service.http) {
        return false;
      }
      if (serviceFilter === 'tls' && !service.tls) {
        return false;
      }
      if (serviceFilter === 'high-risk' && riskLabel(service) !== 'high') {
        return false;
      }

      if (query === '') {
        return true;
      }

      return (
        String(service.port).includes(query) ||
        (service.protocol ?? '').toLowerCase().includes(query) ||
        (service.banner ?? '').toLowerCase().includes(query)
      );
    });

    return filtered.sort((left, right) => {
      const riskOrder = { high: 0, medium: 1, low: 2 };
      const riskCompare =
        riskOrder[riskLabel(left)] - riskOrder[riskLabel(right)];
      if (riskCompare !== 0) {
        return riskCompare;
      }

      return left.port - right.port;
    });
  }, [data?.services, searchValue, serviceFilter]);

  const toggleBody = (serviceID: number) => {
    setExpandedBodies((current) => ({
      ...current,
      [serviceID]: !current[serviceID],
    }));
  };

  return (
    <section className="page host-page pagination-bar-scope">
      <div className="page-header">
        <div>
          <h1 className="host-page-title">{ip}</h1>
          <p>
            {data
              ? [data.country_name, data.city, data.asn_org]
                  .filter(Boolean)
                  .join(' / ')
              : t('hostPage.hostDetailSubtitle')}
          </p>
        </div>
        {data && (
          <div className="header-actions">
            <HostDeepScanButton ip={ip} />
            <HostHttpOpenControl
              ip={ip}
              services={data.services ?? []}
              servicesTotal={data.total}
            />
          </div>
        )}
      </div>
      {isPhablet && data && (
        <MobileTabs
          activeKey={mobileSection}
          ariaLabel={t('hostPage.hostDetailSubtitle')}
          className="host-page-tabs"
          onChange={(key) =>
            setMobileSection(key as 'overview' | 'services' | 'related')
          }
          tabs={[
            { key: 'overview', label: t('hostPage.tabOverview') },
            { key: 'services', label: t('hostPage.tabServices') },
            { key: 'related', label: t('hostPage.tabRelated') },
          ]}
        />
      )}
      {loading && <div className="notice">{t('hostPage.loadingHost')}</div>}
      {error && <div className="error">{error}</div>}
      {data && (
        <>
          {(!isPhablet || mobileSection === 'overview') && (
            <>
          <div className="host-summary-grid">
            <div className="host-summary-item">
              <span>{t('hostPage.firstSeen')}</span>
              <strong>{formatDate(data.first_seen)}</strong>
            </div>
            <div className="host-summary-item">
              <span>{t('hostPage.lastSeen')}</span>
              <strong>{formatDate(data.last_seen)}</strong>
            </div>
            <div className="host-summary-item">
              <span>{t('hostPage.geo')}</span>
              <strong>
                {[data.country_code, data.city].filter(Boolean).join(' / ') ||
                  t('common.na')}
              </strong>
            </div>
            <div className="host-summary-item">
              <span>{t('hostPage.asn')}</span>
              <strong>{data.asn ? `AS${data.asn}` : t('common.na')}</strong>
            </div>
            {data.ptr_hostname && (
              <div className="host-summary-item">
                <span>{t('hostPage.hostname')}</span>
                <strong className="cell-mono">{data.ptr_hostname}</strong>
              </div>
            )}
            <div className="host-summary-item">
              <span>{t('hostPage.services')}</span>
              <strong>{data.total}</strong>
            </div>
          </div>
          <HostRiskPanel ip={data.ip} riskScore={data.risk_score ?? 0} />
          <HostRiskHistoryChart ip={data.ip} />
          <HostRecommendationsPanel ip={data.ip} />
          <LazyHostLocationMap host={data} />
          <HostDnsTable loading={loading} records={data.dns ?? []} />
            </>
          )}
          {(!isPhablet || mobileSection === 'related') && (
          <RelatedHostsTable
            items={related}
            limit={relatedLimit}
            loading={relatedLoading}
            onPageChange={setRelatedPage}
            page={relatedPage}
            total={relatedTotal}
          />
          )}
          {(!isPhablet || mobileSection === 'services') && (
          <>
          <div className="panel host-toolbar pagination-scroll-anchor host-toolbar--sticky">
            <div className="segmented-control">
              {(['all', 'http', 'tls', 'high-risk'] as const).map((value) => (
                <button
                  className={
                    serviceFilter === value ? 'segmented-active' : 'secondary'
                  }
                  key={value}
                  onClick={() => setServiceFilter(value)}
                  type="button"
                >
                  {value === 'all'
                    ? t('hostPage.filterAllServices')
                    : value === 'high-risk'
                      ? t('hostPage.filterHighRiskOnly')
                      : value === 'http'
                        ? t('hostPage.http')
                        : value === 'tls'
                          ? t('hostPage.tls')
                          : String(value)}
                </button>
              ))}
            </div>
            <input
              onChange={(event) => setSearchValue(event.target.value)}
              placeholder={t('hostPage.filterPh')}
              value={searchValue}
            />
          </div>
          <div className="service-list">
            {services.map((service) => (
              <article className="service-panel" key={service.id}>
                <header className="service-header">
                  <div className="service-title-line">
                    <strong className="cell-mono">
                      {service.port}/{service.transport}
                    </strong>
                    <span
                      className={`risk-badge ${riskScoreClass(service.risk_score)}`}
                      title={service.risk_factors?.join(', ')}
                    >
                      {service.risk_score}
                    </span>
                    <span>{service.protocol ?? 'tcp'}</span>
                  </div>
                  <small>{formatDate(service.last_seen)}</small>
                </header>
                {(service.protocol ?? '').toLowerCase() === 'rtsp' && (
                  <details
                    className="host-protocol-details"
                    open={!isPhablet}
                  >
                    <summary>{t('hostPage.protocolBlock')}</summary>
                  <RtspSnapshotBlock
                    defaultWireTransport={
                      service.transport?.toLowerCase() === 'udp' ? 'udp' : 'tcp'
                    }
                    hostIp={ip}
                    pathCue={
                      rtspPathCue !== null && rtspPathCue.port === service.port
                        ? ({
                            path: rtspPathCue.path,
                            nonce: rtspPathCue.nonce,
                          } satisfies RtspPathCue)
                        : null
                    }
                    port={service.port}
                  />
                  </details>
                )}
                {hostServiceEligibleForOnvif(service) && (
                  <details
                    className="host-protocol-details"
                    open={!isPhablet}
                  >
                    <summary>{t('hostPage.protocolBlock')}</summary>
                  <OnvifCommandBlock
                    defaultScheme={defaultOnvifScheme(service)}
                    hostIp={ip}
                    onRtspStreamSuggested={(spec) => {
                      setRtspPathCue({
                        port: spec.port,
                        path: spec.path,
                        nonce: Date.now(),
                      });
                    }}
                    port={service.port}
                  />
                  </details>
                )}
                {hasServiceDetails(service) ? (
                  <div className="service-details-row">
                    <div className="service-detail-controls">
                    <details className="service-details">
                      <summary className="service-details-summary">
                        {t('hostPage.details')}
                      </summary>
                      {service.banner && (
                        <pre className="host-pre">{service.banner}</pre>
                      )}
                      {service.http && (
                        <section className="host-section">
                          <h3>
                            {t('hostPage.http')}
                            {service.http.http3_supported && (
                              <span className="http3-badge" title="Alt-Svc">
                                {t('hostPage.http3')}
                              </span>
                            )}
                          </h3>
                          {service.http.has_screenshot && (
                            <HttpScreenshotBlock
                              hostIp={ip}
                              serviceId={service.id}
                            />
                          )}
                          <div className="host-kv-grid">
                            <span>{t('hostPage.status')}</span>
                            <strong>
                              {service.http.status_code ?? t('common.na')}
                            </strong>
                            <span>{t('hostPage.server')}</span>
                            <strong>
                              {service.http.server ?? t('common.na')}
                            </strong>
                            <span>{t('hostPage.title')}</span>
                            <strong>
                              {service.http.title ?? t('common.na')}
                            </strong>
                            {service.http.redirect_url && (
                              <>
                                <span>{t('hostPage.redirect')}</span>
                                <strong className="cell-mono">
                                  {service.http.redirect_url}
                                </strong>
                              </>
                            )}
                            {service.http.security_headers && (
                              <>
                                <span>{t('hostPage.hsts')}</span>
                                <strong className="cell-mono">
                                  {service.http.security_headers.hsts ?? (
                                    <span className="text-muted">
                                      {t('hostPage.absent')}
                                    </span>
                                  )}
                                </strong>
                                <span>{t('hostPage.csp')}</span>
                                <strong className="cell-mono">
                                  {service.http.security_headers.csp ?? (
                                    <span className="text-muted">
                                      {t('hostPage.absent')}
                                    </span>
                                  )}
                                </strong>
                                <span>{t('hostPage.xFrameOptions')}</span>
                                <strong className="cell-mono">
                                  {service.http.security_headers
                                    .x_frame_options ?? (
                                    <span className="text-muted">
                                      {t('hostPage.absent')}
                                    </span>
                                  )}
                                </strong>
                                <span>{t('hostPage.xContentType')}</span>
                                <strong className="cell-mono">
                                  {service.http.security_headers
                                    .x_content_type_options ?? (
                                    <span className="text-muted">
                                      {t('hostPage.absent')}
                                    </span>
                                  )}
                                </strong>
                              </>
                            )}
                            {service.http.technologies &&
                              service.http.technologies.length > 0 && (
                                <>
                                  <span>{t('hostPage.technologies')}</span>
                                  <strong>
                                    {service.http.technologies.join(', ')}
                                  </strong>
                                </>
                              )}
                            {service.http.favicon_hash !== undefined && (
                              <>
                                <span>{t('hostPage.faviconHash')}</span>
                                <strong className="cell-mono">
                                  {service.http.favicon_hash}
                                  <PivotLink
                                    kind="favicon_hash"
                                    value={String(service.http.favicon_hash)}
                                  />
                                </strong>
                              </>
                            )}
                            {service.http.body_sha256 && (
                              <>
                                <span>{t('hostPage.bodyHash')}</span>
                                <strong className="cell-mono">
                                  {service.http.body_sha256}
                                  <PivotLink
                                    kind="body_sha256"
                                    value={service.http.body_sha256}
                                  />
                                </strong>
                              </>
                            )}
                            {service.http.not_found_hash && (
                              <>
                                <span>{t('hostPage.notFoundHash')}</span>
                                <strong className="cell-mono">
                                  {service.http.not_found_hash}
                                </strong>
                              </>
                            )}
                            {service.http.alt_svc && (
                              <>
                                <span>{t('hostPage.altSvc')}</span>
                                <strong className="cell-mono">
                                  {service.http.alt_svc}
                                </strong>
                              </>
                            )}
                          </div>
                          {service.http.security_info && (
                            <HttpSecurityInfoBlock
                              info={service.http.security_info}
                            />
                          )}
                          {service.http.headers &&
                            Object.keys(service.http.headers).length > 0 && (
                              <details className="host-disclosure">
                                <summary className="host-disclosure-summary">
                                  <span className="host-disclosure-leading">
                                    {t('hostPage.headers')}
                                    <span className="host-disclosure-badge">
                                      {Object.keys(service.http.headers).length}
                                    </span>
                                  </span>
                                </summary>
                                <div className="host-disclosure-panel">
                                  <table className="host-disclosure-table">
                                    <tbody>
                                      {Object.entries(service.http.headers)
                                        .sort(([a], [b]) => a.localeCompare(b))
                                        .map(([name, value]) => (
                                          <tr key={name}>
                                            <th className="cell-mono">
                                              {name}
                                            </th>
                                            <td className="cell-mono">
                                              {value}
                                            </td>
                                          </tr>
                                        ))}
                                    </tbody>
                                  </table>
                                </div>
                              </details>
                            )}
                          {service.http.redirect_chain &&
                            service.http.redirect_chain.length > 1 && (
                              <details className="host-disclosure">
                                <summary className="host-disclosure-summary">
                                  <span className="host-disclosure-leading">
                                    {t('hostPage.redirectChain')}
                                    <span className="host-disclosure-badge">
                                      {t('hostPage.redirectHops', {
                                        count:
                                          service.http.redirect_chain.length,
                                      })}
                                    </span>
                                  </span>
                                </summary>
                                <div className="host-disclosure-panel">
                                  <ol className="host-disclosure-ordered">
                                    {service.http.redirect_chain.map(
                                      (hop, index) => (
                                        <li key={index}>
                                          <span className="http-redirect-status">
                                            {hop.status_code}
                                          </span>{' '}
                                          <span className="cell-mono">
                                            {hop.url}
                                          </span>
                                          {hop.location && (
                                            <>
                                              {' → '}
                                              <span className="cell-mono">
                                                {hop.location}
                                              </span>
                                            </>
                                          )}
                                        </li>
                                      )
                                    )}
                                  </ol>
                                </div>
                              </details>
                            )}
                          {service.http.robots_txt && (
                            <details className="host-disclosure">
                              <summary className="host-disclosure-summary">
                                <span className="host-disclosure-leading">
                                  {t('hostPage.robotsTxt')}
                                </span>
                              </summary>
                              <div className="host-disclosure-panel">
                                <pre className="host-pre host-disclosure-pre">
                                  {service.http.robots_txt}
                                </pre>
                              </div>
                            </details>
                          )}
                          {service.http.security_txt && (
                            <details className="host-disclosure">
                              <summary className="host-disclosure-summary">
                                <span className="host-disclosure-leading">
                                  {t('hostPage.securityTxt')}
                                </span>
                              </summary>
                              <div className="host-disclosure-panel">
                                <pre className="host-pre host-disclosure-pre">
                                  {service.http.security_txt}
                                </pre>
                              </div>
                            </details>
                          )}
                          {service.http.body && (
                            <>
                              <pre
                                className={`host-pre host-body ${
                                  expandedBodies[service.id]
                                    ? 'host-body-expanded'
                                    : 'host-body-collapsed'
                                }`}
                              >
                                {expandedBodies[service.id]
                                  ? service.http.body
                                  : service.http.body.slice(
                                      0,
                                      BODY_PREVIEW_CHARS
                                    )}
                              </pre>
                              {service.http.body.length >
                                BODY_PREVIEW_CHARS && (
                                <button
                                  className="secondary host-body-toggle"
                                  onClick={() => toggleBody(service.id)}
                                  type="button"
                                >
                                  {expandedBodies[service.id]
                                    ? t('hostPage.showLess')
                                    : t('hostPage.showMore')}
                                </button>
                              )}
                            </>
                          )}
                        </section>
                      )}
                      {service.tls && (
                        <section className="host-section">
                          <h3>
                            {t('hostPage.tls')}
                            {service.tls.security_grade && (
                              <>
                                {' '}
                                <TlsGradeBadge
                                  grade={service.tls.security_grade}
                                />
                              </>
                            )}
                          </h3>
                          <div className="host-kv-grid">
                            <span>{t('hostPage.subject')}</span>
                            <strong>
                              {service.tls.subject ?? t('common.na')}
                            </strong>
                            <span>{t('hostPage.issuer')}</span>
                            <strong>
                              {service.tls.issuer ?? t('common.na')}
                            </strong>
                            {service.tls.not_after && (
                              <>
                                <span>{t('hostPage.expires')}</span>
                                <strong
                                  className={
                                    service.tls.days_until_expiry !== undefined
                                      ? tlsExpiryClass(
                                          service.tls.days_until_expiry
                                        )
                                      : ''
                                  }
                                >
                                  {service.tls.not_after.slice(0, 10)}
                                  {service.tls.days_until_expiry !==
                                    undefined && (
                                    <>
                                      {' '}
                                      <span className="text-muted">
                                        (
                                        {service.tls.days_until_expiry < 0
                                          ? t('hostPage.expired')
                                          : t('hostPage.expiresDays', {
                                              count:
                                                service.tls.days_until_expiry,
                                            })}
                                        )
                                      </span>
                                    </>
                                  )}
                                </strong>
                              </>
                            )}
                            <span>{t('hostPage.fingerprintSha')}</span>
                            <strong className="cell-mono">
                              {service.tls.fingerprint_sha256 ?? t('common.na')}
                              {service.tls.fingerprint_sha256 && (
                                <PivotLink
                                  kind="tls_fingerprint"
                                  value={service.tls.fingerprint_sha256}
                                />
                              )}
                            </strong>
                            {service.tls.sans &&
                              service.tls.sans.length > 0 && (
                                <>
                                  <span>{t('hostPage.sans')}</span>
                                  <strong className="cell-mono">
                                    {service.tls.sans.join(', ')}
                                  </strong>
                                </>
                              )}
                            {service.tls.tls_version && (
                              <>
                                <span>{t('hostPage.tlsVersion')}</span>
                                <strong className="cell-mono">
                                  {service.tls.tls_version}
                                </strong>
                              </>
                            )}
                            {service.tls.cipher_suite && (
                              <>
                                <span>{t('hostPage.cipherSuite')}</span>
                                <strong className="cell-mono">
                                  {service.tls.cipher_suite}
                                </strong>
                              </>
                            )}
                            {service.tls.jarm_fingerprint && (
                              <>
                                <span>{t('hostPage.jarm')}</span>
                                <strong className="cell-mono">
                                  {service.tls.jarm_fingerprint}
                                  <PivotLink
                                    kind="jarm"
                                    value={service.tls.jarm_fingerprint}
                                  />
                                </strong>
                              </>
                            )}
                            {service.tls.ja3s_hash && (
                              <>
                                <span>{t('hostPage.ja3s')}</span>
                                <strong className="cell-mono">
                                  {service.tls.ja3s_hash}
                                  <PivotLink
                                    kind="ja3s"
                                    value={service.tls.ja3s_hash}
                                  />
                                </strong>
                              </>
                            )}
                            {service.tls.ja4s_hash && (
                              <>
                                <span>{t('hostPage.ja4s')}</span>
                                <strong className="cell-mono">
                                  {service.tls.ja4s_hash}
                                  <PivotLink
                                    kind="ja4s"
                                    value={service.tls.ja4s_hash}
                                  />
                                </strong>
                              </>
                            )}
                          </div>
                          {service.tls.findings &&
                            service.tls.findings.length > 0 && (
                              <TlsFindingsBlock
                                findings={service.tls.findings}
                              />
                            )}
                          {service.tls.chain &&
                            service.tls.chain.length > 0 && (
                              <details className="host-disclosure">
                                <summary className="host-disclosure-summary">
                                  <span className="host-disclosure-leading">
                                    {t('hostPage.certChain')}
                                    <span className="host-disclosure-badge">
                                      {service.tls.chain.length}
                                    </span>
                                  </span>
                                </summary>
                                <div className="host-disclosure-panel">
                                  <ol className="host-disclosure-chain">
                                    {service.tls.chain.map((node) => (
                                      <li
                                        className="tls-chain-node"
                                        key={`${node.position}-${node.fingerprint_sha256 ?? ''}`}
                                      >
                                        <div className="host-kv-grid">
                                          <span>{t('hostPage.position')}</span>
                                          <strong>{node.position}</strong>
                                          <span>{t('hostPage.subject')}</span>
                                          <strong className="cell-mono">
                                            {node.subject ?? t('common.na')}
                                          </strong>
                                          <span>{t('hostPage.issuer')}</span>
                                          <strong className="cell-mono">
                                            {node.issuer ?? t('common.na')}
                                          </strong>
                                          {node.not_after && (
                                            <>
                                              <span>
                                                {t('hostPage.expires')}
                                              </span>
                                              <strong>
                                                {node.not_after.slice(0, 10)}
                                              </strong>
                                            </>
                                          )}
                                          {node.fingerprint_sha256 && (
                                            <>
                                              <span>
                                                {t('hostPage.fingerprintSha')}
                                              </span>
                                              <strong className="cell-mono">
                                                {node.fingerprint_sha256}
                                              </strong>
                                            </>
                                          )}
                                        </div>
                                      </li>
                                    ))}
                                  </ol>
                                </div>
                              </details>
                            )}
                        </section>
                      )}
                      {service.ssh && (
                        <section className="host-section">
                          <h3>{t('hostPage.ssh')}</h3>
                          <div className="host-kv-grid">
                            <span>{t('hostPage.version')}</span>
                            <strong className="cell-mono">
                              {service.ssh.server_version ?? t('common.na')}
                            </strong>
                            <span>{t('hostPage.hostKey')}</span>
                            <strong className="cell-mono">
                              {service.ssh.host_key_type
                                ? `${service.ssh.host_key_type}`
                                : t('common.na')}
                            </strong>
                            {service.ssh.host_key_fingerprint && (
                              <>
                                <span>{t('hostPage.fingerprintSha')}</span>
                                <strong className="cell-mono">
                                  {service.ssh.host_key_fingerprint}
                                </strong>
                              </>
                            )}
                            {service.ssh.kex_algorithms &&
                              service.ssh.kex_algorithms.length > 0 && (
                                <>
                                  <span>{t('hostPage.kexAlgorithms')}</span>
                                  <strong className="cell-mono">
                                    {service.ssh.kex_algorithms.join(', ')}
                                  </strong>
                                </>
                              )}
                            {service.ssh.host_key_algorithms &&
                              service.ssh.host_key_algorithms.length > 0 && (
                                <>
                                  <span>{t('hostPage.hostKeyAlgorithms')}</span>
                                  <strong className="cell-mono">
                                    {service.ssh.host_key_algorithms.join(', ')}
                                  </strong>
                                </>
                              )}
                          </div>
                        </section>
                      )}
                      {service.smtp && (
                        <section className="host-section">
                          <h3>{t('hostPage.smtp')}</h3>
                          <div className="host-kv-grid">
                            <span>{t('hostPage.banner')}</span>
                            <strong className="cell-mono">
                              {service.smtp.banner ?? t('common.na')}
                            </strong>
                            <span>{t('hostPage.starttls')}</span>
                            <strong>
                              {service.smtp.starttls
                                ? t('common.yes')
                                : t('common.no')}
                            </strong>
                            {service.smtp.auth_methods &&
                              service.smtp.auth_methods.length > 0 && (
                                <>
                                  <span>{t('hostPage.authMethods')}</span>
                                  <strong className="cell-mono">
                                    {service.smtp.auth_methods.join(', ')}
                                  </strong>
                                </>
                              )}
                            {service.smtp.max_message_size !== undefined && (
                              <>
                                <span>{t('hostPage.maxSizeLabel')}</span>
                                <strong>
                                  {t('hostPage.maxSizeMb', {
                                    value: (
                                      service.smtp.max_message_size /
                                      (1024 * 1024)
                                    ).toFixed(1),
                                  })}
                                </strong>
                              </>
                            )}
                            {service.smtp.capabilities &&
                              service.smtp.capabilities.length > 0 && (
                                <>
                                  <span>{t('hostPage.capabilities')}</span>
                                  <strong className="cell-mono">
                                    {service.smtp.capabilities.join(', ')}
                                  </strong>
                                </>
                              )}
                          </div>
                        </section>
                      )}
                      {service.fingerprint && (
                        <section className="host-section">
                          <h3>{t('hostPage.fingerprint')}</h3>
                          <div className="host-kv-grid">
                            <span>{t('hostPage.product')}</span>
                            <strong>{service.fingerprint.product}</strong>
                            <span>{t('hostPage.version')}</span>
                            <strong>
                              {service.fingerprint.version ?? t('common.na')}
                            </strong>
                            <span>{t('hostPage.edition')}</span>
                            <strong>
                              {service.fingerprint.edition ?? t('common.na')}
                            </strong>
                            <span>{t('hostPage.authRequired')}</span>
                            <strong>
                              {service.fingerprint.auth_required === undefined
                                ? t('common.na')
                                : service.fingerprint.auth_required
                                  ? t('common.yes')
                                  : t('common.no')}
                            </strong>
                            <span>{t('hostPage.tlsRequired')}</span>
                            <strong>
                              {service.fingerprint.tls_required === undefined
                                ? t('common.na')
                                : service.fingerprint.tls_required
                                  ? t('common.yes')
                                  : t('common.no')}
                            </strong>
                            <span>{t('hostPage.cluster')}</span>
                            <strong>
                              {[
                                service.fingerprint.cluster_name,
                                service.fingerprint.cluster_role,
                              ]
                                .filter(Boolean)
                                .join(' / ') || t('common.na')}
                            </strong>
                            <span>{t('hostPage.anonymous')}</span>
                            <strong>
                              {service.fingerprint.anonymous
                                ? t('common.yes')
                                : t('common.no')}
                            </strong>
                          </div>
                        </section>
                      )}
                      {service.cves && service.cves.length > 0 && (
                        <section className="host-section">
                          <details className="host-disclosure" open>
                            <summary className="host-disclosure-summary">
                              <span className="host-disclosure-leading">
                                <ChevronDown aria-hidden size={14} />
                                <span>{t('hostPage.knownCves')}</span>
                                <span className="host-disclosure-badge">
                                  {cveCountTotal(service)}
                                </span>
                              </span>
                            </summary>
                            <div className="host-disclosure-panel">
                              <ul className="cve-list">
                                {service.cves.map((cve) => (
                                  <li className="cve-row" key={cve.id}>
                                    <span
                                      className={cveSeverityClass(cve.severity)}
                                    >
                                      {cve.severity ?? 'UNKNOWN'}
                                    </span>
                                    <a
                                      className="cve-row-id"
                                      href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                                      rel="noreferrer"
                                      target="_blank"
                                    >
                                      {cve.id}
                                    </a>
                                    {cve.cvss_score !== undefined && (
                                      <span className="cve-row-score">
                                        {cve.cvss_score.toFixed(1)}
                                      </span>
                                    )}
                                    {cve.summary && (
                                      <span className="cve-row-summary">
                                        {cve.summary}
                                      </span>
                                    )}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          </details>
                        </section>
                      )}
                      {service.fingerprint &&
                        (!service.cves || service.cves.length === 0) &&
                        service.fingerprint.version && (
                          <section className="host-section">
                            <p className="muted-text">
                              {t('hostPage.noCvesForVersion')}
                            </p>
                          </section>
                        )}
                    </details>
                    <ServiceExplainDisclosure
                      label={t('risk.explain.openService')}
                      serviceId={service.id}
                    />
                    </div>
                    <CopyButton
                      className="service-details-copy"
                      label={t('hostPage.copyServiceJson')}
                      text={JSON.stringify(service, null, 2)}
                    />
                  </div>
                ) : (
                  <div className="service-details-row">
                    <div className="service-detail-controls">
                      <ServiceExplainDisclosure
                        label={t('risk.explain.openService')}
                        serviceId={service.id}
                      />
                    </div>
                  </div>
                )}
              </article>
            ))}
            {!loading && services.length === 0 && (
              <div className="notice">{t('hostPage.noServicesMatch')}</div>
            )}
          </div>
      <PaginationBarDock>
            <div className="panel pagination-bar">
              <span className="pagination-bar-meta">
                {t('hostPage.paginationComma', {
                  page: data.page,
                  pages: Math.max(1, Math.ceil(data.total / data.limit)),
                  total: data.total,
                })}
              </span>
              <div className="header-actions pagination-bar-controls">
                <label className="muted-text pagination-bar-limit">
                  {t('scansPage.limitLabel')}
                  <Select
                    compact
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
                    disabled={data.page <= 1 || loading}
                    onClick={() => {
                      setParams((prev) => {
                        const next = new URLSearchParams(prev);
                        next.set('page', String(currentPage - 1));
                        next.set('limit', String(currentLimit));
                        return next;
                      });
                    }}
                    type="button"
                  >
                    {t('common.prev')}
                  </button>
                  <button
                    className="secondary"
                    disabled={
                      data.page >=
                        Math.max(1, Math.ceil(data.total / data.limit)) || loading
                    }
                    onClick={() => {
                      setParams((prev) => {
                        const next = new URLSearchParams(prev);
                        next.set('page', String(currentPage + 1));
                        next.set('limit', String(currentLimit));
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
              </>
          )}
        </>
      )}
    </section>
  );
}
