import { ShieldOff } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { EmptyState } from '@components/EmptyState';
import { cveSeverityClass } from '@helpers/cveSeverity';
import { useAppSelector } from '@store/store';

export function DashboardTopCVEs() {
  const { t } = useTranslation();
  const { data, loading } = useAppSelector((state) => state.dashboard);
  const items = data?.top_cves ?? [];

  return (
    <section
      aria-label={t('dashboard.topCvesAria')}
      className="dashboard-panel dashboard-top-cves"
    >
      <header className="dashboard-panel-header">
        <h2 className="dashboard-panel-title">{t('dashboard.topCvesTitle')}</h2>
      </header>
      {loading && !data && <div className="dashboard-panel-skeleton" />}
      {!loading && items.length === 0 && (
        <EmptyState
          icon={<ShieldOff aria-hidden size={20} />}
          title={t('dashboard.topCvesEmpty')}
        />
      )}
      {items.length > 0 && (
        <ul className="dashboard-top-cves-list">
          {items.map((cve) => (
            <li className="dashboard-top-cves-row" key={cve.id}>
              <span className={cveSeverityClass(cve.severity)}>
                {cve.severity ?? t('dashboard.topCvesUnknown')}
              </span>
              <a
                className="dashboard-top-cves-id"
                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                rel="noreferrer"
                target="_blank"
              >
                {cve.id}
              </a>
              {cve.cvss_score !== undefined && (
                <span className="dashboard-top-cves-score">
                  {cve.cvss_score.toFixed(1)}
                </span>
              )}
              <span className="dashboard-top-cves-services">
                {t('dashboard.topCvesServiceCount', {
                  count: cve.services,
                })}
              </span>
              {cve.summary && (
                <span className="dashboard-top-cves-summary">
                  {cve.summary}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
