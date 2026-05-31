import { lazy, Suspense } from 'react';
import { useTranslation } from 'react-i18next';

type DashboardHostMapProps = {
  loading: boolean;
  error: string | null;
  countries: import('@/types/api').DashboardMapCountryRow[];
  points: import('@/types/api').DashboardMapPointRow[];
  pointsSource?: import('@/types/api').DashboardMapPointsSource;
};

const DashboardHostMapLazy = lazy(() =>
  import('@features/Dashboard/DashboardHostMap').then((module) => ({
    default: module.DashboardHostMap,
  }))
);

type Props = DashboardHostMapProps;

function DashboardHostMapFallback() {
  const { t } = useTranslation();

  return (
    <div className="dashboard-map-card">
      <div className="dashboard-map-card-header">
        <span className="dashboard-panel-title">
          {t('dashboard.mapHostFootprint')}
        </span>
      </div>
      <div
        aria-busy="true"
        aria-label={t('dashboard.mapLoadingAria')}
        className="dashboard-map-skeleton dashboard-map-skeleton--card"
      />
    </div>
  );
}

export function LazyDashboardHostMap(props: Props) {
  return (
    <Suspense fallback={<DashboardHostMapFallback />}>
      <DashboardHostMapLazy {...props} />
    </Suspense>
  );
}
