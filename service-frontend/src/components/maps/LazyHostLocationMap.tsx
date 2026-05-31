import { lazy, Suspense } from 'react';
import { useTranslation } from 'react-i18next';

type HostLocationMapProps = {
  host: import('@/types/hosts').Host;
};

const HostLocationMapLazy = lazy(() =>
  import('@features/Host/HostLocationMap').then((module) => ({
    default: module.HostLocationMap,
  }))
);

type Props = HostLocationMapProps;

function HostLocationMapFallback() {
  const { t } = useTranslation();

  return (
    <div className="host-map-card">
      <div className="host-map-card-header">
        <span className="dashboard-panel-title">
          {t('hostPage.locationTitle')}
        </span>
      </div>
      <div
        aria-busy="true"
        aria-label={t('common.loading')}
        className="dashboard-map-skeleton dashboard-map-skeleton--card"
      />
    </div>
  );
}

export function LazyHostLocationMap(props: Props) {
  return (
    <Suspense fallback={<HostLocationMapFallback />}>
      <HostLocationMapLazy {...props} />
    </Suspense>
  );
}
