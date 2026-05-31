import * as Dialog from '@radix-ui/react-dialog';
import { Globe, Hand, Info, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { LazyCountriesCobeGlobe } from '@components/maps/LazyCountriesCobeGlobe';
import { resolveCountryCentroid } from '@helpers/dashboardMapCoords';
import {
  buildCountryGlobeMarkers,
  buildHostGlobeMarkers,
  formatDashboardGlobeStats,
  hostGlobeLimit,
  plottedToCountryCountRows,
  resolveGlobeHostPoints,
  subsampleMapPoints,
  type DashboardMapEmptyKind,
  type PlottedMapCountry,
} from '@helpers/dashboardMapHelpers';
import { COBE_GLOBE_SAMPLES_FULL } from '@helpers/cobeGlobePresets';
import type {
  DashboardGlobeViewMode,
  DashboardMapCountryRow,
  DashboardMapPointRow,
  DashboardMapPointsSource,
} from '@/types/api';

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  loading: boolean;
  error: string | null;
  mapEmptyKind: DashboardMapEmptyKind | null;
  countries: DashboardMapCountryRow[];
  plotted: PlottedMapCountry[];
  points: DashboardMapPointRow[];
  pointsSource?: DashboardMapPointsSource;
};

const legendLimit = 8;

const emptyMessageKey: Record<DashboardMapEmptyKind, string> = {
  no_country: 'dashboard.mapEmptyNoCountry',
  no_centroid: 'dashboard.mapEmptyNoCentroid',
};

export function DashboardHostGlobeOverlay({
  open,
  onOpenChange,
  loading,
  error,
  mapEmptyKind,
  countries,
  plotted,
  points,
  pointsSource,
}: Props) {
  const { t } = useTranslation();

  const resolvedHostData = useMemo(
    () => resolveGlobeHostPoints(points, plotted, pointsSource),
    [points, plotted, pointsSource]
  );

  const hasGeoHosts = resolvedHostData.source === 'geo' && resolvedHostData.points.length > 0;

  const [viewMode, setViewMode] = useState<DashboardGlobeViewMode>(() =>
    hasGeoHosts ? 'hosts' : 'countries'
  );
  const [highlightedCountry, setHighlightedCountry] = useState<string | null>(
    null
  );
  const [focusLocation, setFocusLocation] = useState<{
    lat: number;
    lng: number;
  } | null>(null);

  const countryRows = useMemo(
    () => plottedToCountryCountRows(plotted),
    [plotted]
  );

  const hostPoints = useMemo(
    () => subsampleMapPoints(resolvedHostData.points, hostGlobeLimit),
    [resolvedHostData.points]
  );

  const usesCentroidFallback = resolvedHostData.source === 'country_centroid';

  const legend = useMemo(
    () => [...plotted].sort((a, b) => b.count - a.count).slice(0, legendLimit),
    [plotted]
  );

  const legendMax = legend[0]?.count ?? 0;

  const markers = useMemo(() => {
    if (viewMode === 'hosts' && hostPoints.length > 0) {
      return buildHostGlobeMarkers(hostPoints, highlightedCountry);
    }

    return buildCountryGlobeMarkers(countryRows, highlightedCountry);
  }, [viewMode, hostPoints, countryRows, highlightedCountry]);

  const onGlobeCount =
    viewMode === 'hosts' && hostPoints.length > 0
      ? hostPoints.length
      : countryRows.length;

  const showHostsEmpty =
    viewMode === 'hosts' &&
    hostPoints.length === 0 &&
    countryRows.length === 0 &&
    !loading &&
    !error;

  const showGlobe =
    !loading && !error && !mapEmptyKind && !showHostsEmpty && markers.length > 0;

  const globeStats = useMemo(
    () => formatDashboardGlobeStats(countries, plotted.length, onGlobeCount, t),
    [countries, plotted.length, onGlobeCount, t]
  );

  const handleLegendFocus = (countryCode: string) => {
    const code = countryCode.trim().toUpperCase().slice(0, 2);
    setHighlightedCountry(code);

    const centroid = resolveCountryCentroid(code);
    if (centroid) {
      setFocusLocation({ lat: centroid.lat, lng: centroid.lng });
    }
  };

  const clearLegendFocus = () => {
    setHighlightedCountry(null);
    setFocusLocation(null);
  };

  return (
    <Dialog.Root onOpenChange={onOpenChange} open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay dashboard-globe-overlay" />
        <Dialog.Content
          aria-describedby={undefined}
          className="dashboard-globe-shell"
        >
          <header className="dashboard-globe-header">
            <div className="dashboard-globe-header-text">
              <span aria-hidden className="dashboard-globe-header-icon">
                <Globe size={18} />
              </span>
              <div className="dashboard-globe-heading">
                <Dialog.Title className="dashboard-globe-title">
                  {t('dashboard.mapHostFootprint')}
                </Dialog.Title>
                {!loading && !error && globeStats && (
                  <p className="dashboard-globe-stats">
                    <span className="dashboard-globe-stats-base">
                      {globeStats.base}
                    </span>
                    <span aria-hidden className="dashboard-globe-stats-sep">
                      ·
                    </span>
                    <span className="dashboard-globe-stats-globe">
                      {globeStats.globe}
                    </span>
                  </p>
                )}
              </div>
            </div>
            <div className="dashboard-globe-header-actions">
              <div
                className="dashboard-globe-mode-toggle segmented-control"
                role="group"
              >
                <button
                  aria-pressed={viewMode === 'hosts'}
                  className={viewMode === 'hosts' ? 'segmented-active' : undefined}
                  onClick={() => setViewMode('hosts')}
                  type="button"
                >
                  {t('dashboard.mapGlobeModeHosts')}
                </button>
                <button
                  aria-pressed={viewMode === 'countries'}
                  className={
                    viewMode === 'countries' ? 'segmented-active' : undefined
                  }
                  disabled={countryRows.length === 0}
                  onClick={() => setViewMode('countries')}
                  type="button"
                >
                  {t('dashboard.mapGlobeModeCountries')}
                </button>
              </div>
              <Dialog.Close asChild>
                <button
                  aria-label={t('dashboard.mapGlobeClose')}
                  className="secondary dashboard-globe-close"
                  type="button"
                >
                  <X aria-hidden size={18} />
                </button>
              </Dialog.Close>
            </div>
          </header>

          {error && (
            <div className="error dashboard-globe-body-message">{error}</div>
          )}
          {loading && (
            <div
              aria-busy="true"
              aria-label={t('dashboard.mapGlobeLoadingAria')}
              className="dashboard-map-skeleton dashboard-map-skeleton--fill"
            />
          )}
          {mapEmptyKind && (
            <div className="dashboard-globe-body-message">
              {t(emptyMessageKey[mapEmptyKind])}
            </div>
          )}
          {showHostsEmpty && (
            <div className="dashboard-globe-body-message">
              {t('dashboard.mapGlobeEmptyHosts')}
            </div>
          )}
          {showGlobe && (
            <>
              <div className="dashboard-globe-stage">
                <LazyCountriesCobeGlobe
                  autoRotate
                  className="dashboard-globe-canvas-wrap"
                  focusLocation={focusLocation}
                  interactive
                  mapSamples={COBE_GLOBE_SAMPLES_FULL}
                  markers={markers}
                />
              </div>
              <footer className="dashboard-globe-footer">
                {legend.length > 0 && (
                  <ul
                    aria-label={t('dashboard.mapGlobeLegendAria')}
                    className="dashboard-globe-legend"
                  >
                    {legend.map((row) => {
                      const ratio =
                        legendMax > 0
                          ? Math.max(0.08, row.count / legendMax)
                          : 0;
                      const isActive =
                        highlightedCountry ===
                        row.country_code.trim().toUpperCase().slice(0, 2);

                      return (
                        <li key={row.country_code}>
                          <Link
                            className={[
                              'dashboard-globe-legend-chip',
                              isActive
                                ? 'dashboard-globe-legend-chip--active'
                                : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                            onBlur={clearLegendFocus}
                            onFocus={() => handleLegendFocus(row.country_code)}
                            onMouseEnter={() =>
                              handleLegendFocus(row.country_code)
                            }
                            onMouseLeave={clearLegendFocus}
                            to={`/search?country=${encodeURIComponent(row.country_code)}`}
                          >
                            <span className="dashboard-globe-legend-code">
                              {row.country_code}
                            </span>
                            <span
                              aria-hidden
                              className="dashboard-globe-legend-bar"
                            >
                              <span
                                className="dashboard-globe-legend-bar-fill"
                                style={{ width: `${String(ratio * 100)}%` }}
                              />
                            </span>
                            <span className="dashboard-globe-legend-count">
                              {t('dashboard.mapPopupHosts', {
                                count: row.count,
                              })}
                            </span>
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                )}
                <div
                  aria-label={t('dashboard.mapGlobeHintsAria')}
                  className="dashboard-globe-hints"
                  role="note"
                >
                  <span className="dashboard-globe-hint-chip dashboard-globe-hint-chip--meta">
                    <Info aria-hidden size={12} strokeWidth={2.25} />
                    <span>
                      {usesCentroidFallback
                        ? t('dashboard.mapGlobeHintCentroid')
                        : t('dashboard.mapGlobeHint')}
                    </span>
                  </span>
                  <span className="dashboard-globe-hint-chip">
                    <Hand aria-hidden size={12} strokeWidth={2.25} />
                    <span>{t('dashboard.mapGlobeDragHint')}</span>
                  </span>
                  <span className="dashboard-globe-hint-chip">
                    <kbd>Esc</kbd>
                    <span>{t('dashboard.mapGlobeEscLabel')}</span>
                  </span>
                </div>
              </footer>
            </>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
