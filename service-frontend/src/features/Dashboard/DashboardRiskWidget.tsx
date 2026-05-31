import { Activity } from 'lucide-react';
import { useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { DashboardWidgetTools } from '@components/DashboardWidgetTools';
import { EmptyState } from '@components/EmptyState';
import { useAsyncWidget } from '@/hooks/useAsyncWidget';
import {
  hostIPLiteral,
  hostPathFromScanTarget,
} from '@helpers/hostPathFromScanTarget';
import { getDashboardRisk } from '@services/DashboardAPI';
import { riskScoreClass } from '@features/Host/hostRiskHelpers';

const BUCKET_COLORS: Record<string, string> = {
  '0-25': '#22c55e',
  '26-50': '#facc15',
  '51-75': '#f97316',
  '76-100': '#ef4444',
  low: '#22c55e',
  medium: '#facc15',
  high: '#f97316',
  critical: '#ef4444',
};

function bucketColor(bucket: string): string {
  return BUCKET_COLORS[bucket] ?? BUCKET_COLORS[bucket.toLowerCase()] ?? '#64748b';
}

export function DashboardRiskWidget() {
  const { t } = useTranslation();

  const fetcher = useCallback(() => getDashboardRisk(), []);
  const { data, loading, error, lastUpdated, reload } = useAsyncWidget({
    fetcher,
    fallbackError: t('dashboard.riskLoadFailed'),
  });

  const buckets = data?.score_buckets ?? [];
  const services = data?.top_risky_services ?? [];
  const hosts = data?.top_risky_hosts ?? [];
  const total = buckets.reduce((acc, b) => acc + b.count, 0);

  return (
    <section
      aria-label={t('dashboard.riskAria')}
      className="dashboard-panel dashboard-risk"
    >
      <header className="dashboard-panel-header">
        <h2 className="dashboard-panel-title">{t('dashboard.riskTitle')}</h2>
        <DashboardWidgetTools
          lastUpdated={lastUpdated}
          loading={loading}
          onRefresh={() => void reload()}
        />
      </header>
      {error && <div className="error">{error}</div>}
      {loading && !data && <div className="dashboard-panel-skeleton" />}
      {!loading && total === 0 && (
        <EmptyState
          icon={<Activity aria-hidden size={20} />}
          title={t('dashboard.riskNoScored')}
        />
      )}
      {total > 0 && (
        <>
          <div
            aria-label={t('dashboard.riskTitle')}
            className="dashboard-risk-stacked-bar"
            role="img"
          >
            {buckets.map((bucket) => {
              const pct = total === 0 ? 0 : (bucket.count / total) * 100;
              const color = bucketColor(bucket.bucket);

              if (bucket.count === 0) {
                return null;
              }

              return (
                <span
                  className="dashboard-risk-stacked-segment"
                  key={bucket.bucket}
                  style={{
                    background: color,
                    flexGrow: bucket.count,
                  }}
                  title={`${bucket.bucket}: ${bucket.count.toLocaleString()} (${pct.toFixed(1)}%)`}
                />
              );
            })}
          </div>
          <ul className="dashboard-risk-legend">
            {buckets.map((bucket) => {
              const color = bucketColor(bucket.bucket);

              return (
                <li
                  className="dashboard-risk-legend-item"
                  key={bucket.bucket}
                >
                  <span
                    aria-hidden
                    className="dashboard-risk-legend-dot"
                    style={{ background: color }}
                  />
                  <span className="dashboard-risk-legend-label">
                    {bucket.bucket}
                  </span>
                  <span className="dashboard-risk-legend-value">
                    {bucket.count.toLocaleString()}
                  </span>
                </li>
              );
            })}
          </ul>
          <div className="dashboard-risk-columns">
            <div>
              <p className="dashboard-risk-subtitle">
                {t('dashboard.riskHighSvc')}
              </p>
              {services.length === 0 ? (
                <p className="dashboard-panel-empty">
                  {t('dashboard.riskNoServices')}
                </p>
              ) : (
                <ul className="dashboard-risk-list">
                    {services.map((row) => {
                    const ip = hostIPLiteral(row.host_ip) ?? row.host_ip;

                    return (
                      <li
                        className="dashboard-risk-list-row"
                        key={row.service_id}
                      >
                        <Link
                          className="dashboard-risk-list-target cell-mono"
                          to={`/hosts/${encodeURIComponent(ip)}`}
                          title={`${ip}:${String(row.port)}`}
                        >
                          <span className="dashboard-risk-list-ip">{ip}</span>
                          <span className="dashboard-risk-list-port">
                            :{row.port}
                          </span>
                        </Link>
                        <span
                          className="dashboard-risk-list-meta"
                          title={row.top_factor ?? row.protocol ?? ''}
                        >
                          {row.top_factor ?? row.protocol ?? ''}
                        </span>
                        <span
                          className={`dashboard-risk-list-score risk-badge ${riskScoreClass(row.risk_score)}`}
                        >
                          {row.risk_score}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
            <div>
              <p className="dashboard-risk-subtitle">
                {t('dashboard.riskHighHosts')}
              </p>
              {hosts.length === 0 ? (
                <p className="dashboard-panel-empty">
                  {t('dashboard.riskNoHosts')}
                </p>
              ) : (
                <ul className="dashboard-risk-list">
                  {hosts.map((row) => {
                    const ipLabel = hostIPLiteral(row.ip) ?? row.ip;
                    const path = hostPathFromScanTarget(row.ip);

                    return (
                      <li className="dashboard-risk-list-row" key={row.host_id}>
                        {path ? (
                          <Link
                            className="dashboard-risk-list-target cell-mono"
                            to={path}
                          >
                            <span className="dashboard-risk-list-ip">
                              {ipLabel}
                            </span>
                          </Link>
                        ) : (
                          <span className="dashboard-risk-list-target cell-mono">
                            <span className="dashboard-risk-list-ip">
                              {ipLabel}
                            </span>
                          </span>
                        )}
                        <span
                          className="dashboard-risk-list-meta"
                          title={row.top_factor ?? row.country_code ?? ''}
                        >
                          {row.top_factor ?? row.country_code ?? ''}
                        </span>
                        <span
                          className={`dashboard-risk-list-score risk-badge ${riskScoreClass(row.risk_score)}`}
                        >
                          {row.risk_score}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        </>
      )}
    </section>
  );
}
