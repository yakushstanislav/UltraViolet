import { useTranslation } from 'react-i18next';

type PivotLegendProps = {
  hostCount?: number;
  serviceCount?: number;
};

export function PivotLegend({ hostCount, serviceCount }: PivotLegendProps) {
  const { t } = useTranslation();

  return (
    <div className="pivot-meta">
      {(hostCount !== undefined || serviceCount !== undefined) && (
        <ul className="pivot-stats">
          {hostCount !== undefined && (
            <li className="pivot-stat">
              <span className="pivot-stat-value">{hostCount}</span>
              <span className="pivot-stat-label">{t('pivot.stats.hosts')}</span>
            </li>
          )}
          {serviceCount !== undefined && (
            <li className="pivot-stat">
              <span className="pivot-stat-value">{serviceCount}</span>
              <span className="pivot-stat-label">{t('pivot.stats.services')}</span>
            </li>
          )}
        </ul>
      )}
      <ul className="pivot-legend">
        <li>
          <span className="pivot-legend-dot pivot-legend-dot-host" />
          {t('pivot.legend.host')}
        </li>
        <li>
          <span className="pivot-legend-dot pivot-legend-dot-service" />
          {t('pivot.legend.service')}
        </li>
        <li>
          <span className="pivot-legend-dot pivot-legend-dot-artifact" />
          {t('pivot.legend.artifact')}
        </li>
        <li>
          <span className="pivot-legend-halo pivot-legend-halo-high" />
          {t('pivot.legend.highRisk')}
        </li>
      </ul>
      <p className="pivot-hint">{t('pivot.graphHint')}</p>
    </div>
  );
}
