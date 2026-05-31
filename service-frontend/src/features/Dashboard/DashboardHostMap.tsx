import L from 'leaflet';
import { Globe } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  CircleMarker,
  MapContainer,
  TileLayer,
  Tooltip as LeafletTooltip,
  useMap,
} from 'react-leaflet';
import { useNavigate } from 'react-router-dom';

import {
  formatDashboardMapSubtitle,
  plotDashboardMapCountries,
  resolveDashboardMapEmptyKind,
  resolveGlobeHostPoints,
  type PlottedMapCountry,
} from '@helpers/dashboardMapHelpers';
import { readCssColorString } from '@helpers/themeColors';
import { useTheme } from '@/theme/ThemeProvider';
import type {
  DashboardMapCountryRow,
  DashboardMapPointRow,
  DashboardMapPointsSource,
} from '@/types/api';

import { DashboardHostGlobeOverlay } from './DashboardHostGlobeOverlay';


const tileSoft =
  'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';
const tileNight =
  'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';

type Props = {
  loading: boolean;
  error: string | null;
  countries: DashboardMapCountryRow[];
  points: DashboardMapPointRow[];
  pointsSource?: DashboardMapPointsSource;
};

const defaultCenter: L.LatLngExpression = [20, 0];
const defaultZoom = 2;

// Roughly the Mercator-renderable world extent. Keeps leaflet from showing
// grey space above the north pole / below the south pole.
const worldBounds = L.latLngBounds([-60, -180], [75, 180]);

function MapFitBounds({ plotted }: { plotted: PlottedMapCountry[] }) {
  const map = useMap();

  useEffect(() => {
    if (plotted.length === 0) {
      map.fitBounds(worldBounds, { padding: [10, 10] });

      return;
    }

    const latLngs = plotted.map((p) => L.latLng(p.lat, p.lng));
    const onlyLatLng = latLngs[0];

    if (latLngs.length === 1 && onlyLatLng !== undefined) {
      map.setView(onlyLatLng, 5);

      return;
    }

    map.fitBounds(L.latLngBounds(latLngs), { maxZoom: 10, padding: [40, 40] });
  }, [map, plotted]);

  return null;
}

function MapAutoResize({ plotted }: { plotted: PlottedMapCountry[] }) {
  const map = useMap();
  const plottedRef = useRef(plotted);

  useEffect(() => {
    plottedRef.current = plotted;
  }, [plotted]);

  useEffect(() => {
    const container = map.getContainer();

    const refit = () => {
      map.invalidateSize({ animate: false });

      const current = plottedRef.current;

      if (current.length === 0) {
        map.fitBounds(worldBounds, { padding: [10, 10], animate: false });

        return;
      }

      const onlyCurrent = current[0];
      if (current.length === 1 && onlyCurrent !== undefined) {
        map.setView([onlyCurrent.lat, onlyCurrent.lng], 5, { animate: false });

        return;
      }

      const latLngs = current.map((p) => L.latLng(p.lat, p.lng));

      map.fitBounds(L.latLngBounds(latLngs), {
        animate: false,
        maxZoom: 10,
        padding: [40, 40],
      });
    };

    const observer = new ResizeObserver(() => {
      refit();
    });

    observer.observe(container);

    return () => {
      observer.disconnect();
    };
  }, [map]);

  return null;
}

export function DashboardHostMap({
  loading,
  error,
  countries,
  points,
  pointsSource,
}: Props) {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const navigate = useNavigate();
  const [globeOpen, setGlobeOpen] = useState(false);

  useEffect(() => {
    void import('leaflet/dist/leaflet.css');
  }, []);

  const plotted = useMemo(
    () => plotDashboardMapCountries(countries),
    [countries]
  );

  const subtitle = useMemo(
    () => formatDashboardMapSubtitle(countries, t),
    [countries, t]
  );

  const mapEmptyKind = useMemo(
    () => resolveDashboardMapEmptyKind(loading, error, countries, plotted, points),
    [loading, error, countries, plotted, points]
  );

  const mapHasMarkers = plotted.length > 0;

  const tileUrl = useMemo(
    () => (theme === 'dark' ? tileNight : tileSoft),
    [theme]
  );

  const markerPathOptions = useMemo(() => {
    const color = readCssColorString(
      theme === 'dark' ? '--accent' : '--primary',
      theme === 'dark' ? '#22d3ee' : '#7c3aed'
    );

    return {
      color,
      fillColor: color,
      fillOpacity: theme === 'dark' ? 0.42 : 0.38,
      weight: 1,
    };
  }, [theme]);

  const resolvedGlobePoints = useMemo(
    () => resolveGlobeHostPoints(points, plotted, pointsSource),
    [points, plotted, pointsSource]
  );

  const hasGlobeData = mapHasMarkers || resolvedGlobePoints.points.length > 0;

  const globeDisabled = loading || Boolean(error) || !hasGlobeData;

  useEffect(() => {
    if (globeDisabled && globeOpen) {
      setGlobeOpen(false);
    }
  }, [globeDisabled, globeOpen]);

  return (
    <div className="dashboard-map-card">
      <div className="dashboard-map-card-header">
        <span className="dashboard-panel-title">
          {t('dashboard.mapHostFootprint')}
        </span>
        <div className="dashboard-map-card-header-actions">
          {subtitle && !loading && !error && (
            <span className="dashboard-map-card-badge">{subtitle}</span>
          )}
          <button
            aria-label={t('dashboard.mapOpenGlobe')}
            className="secondary dashboard-map-globe-btn"
            disabled={globeDisabled}
            onClick={() => setGlobeOpen(true)}
            type="button"
          >
            <Globe aria-hidden size={16} strokeWidth={2} />
          </button>
        </div>
      </div>
      <DashboardHostGlobeOverlay
        error={error}
        loading={loading}
        countries={countries}
        mapEmptyKind={mapEmptyKind}
        onOpenChange={setGlobeOpen}
        open={globeOpen}
        plotted={plotted}
        points={points}
        pointsSource={pointsSource}
      />
      {error && <div className="error dashboard-map-card-error">{error}</div>}
      {loading && (
        <div
          aria-busy="true"
          aria-label={t('dashboard.mapLoadingAria')}
          className="dashboard-map-skeleton dashboard-map-skeleton--card"
        />
      )}
      {!loading && !error && countries.length === 0 && (
        <div className="dashboard-map-empty">
          {t('dashboard.mapEmptyNoCountry')}
        </div>
      )}
      {!loading && !error && countries.length > 0 && !mapHasMarkers && (
        <div className="dashboard-map-empty">
          {t('dashboard.mapEmptyNoCentroid')}
        </div>
      )}
      {!loading && !error && mapHasMarkers && (
        <div className="dashboard-map-inner">
          <MapContainer
            attributionControl={false}
            center={defaultCenter}
            className="dashboard-leaflet-map"
            maxBounds={worldBounds}
            maxBoundsViscosity={1}
            minZoom={2}
            scrollWheelZoom
            worldCopyJump={false}
            zoom={defaultZoom}
          >
            <TileLayer key={tileUrl} url={tileUrl} />
            <MapFitBounds plotted={plotted} />
            <MapAutoResize plotted={plotted} />
            {plotted.map((row) => (
              <CircleMarker
                center={[row.lat, row.lng]}
                eventHandlers={{
                  click: () => {
                    navigate(
                      `/search?country=${encodeURIComponent(row.country_code)}`,
                    );
                  },
                }}
                key={row.country_code}
                pathOptions={{ ...markerPathOptions, className: 'dashboard-map-marker-clickable' }}
                radius={row.radius}
              >
                <LeafletTooltip
                  className="dashboard-map-tooltip"
                  direction="top"
                  offset={[0, -4]}
                  opacity={1}
                >
                  <strong>{row.country_code}</strong>{' '}
                  <span className="dashboard-map-tooltip-meta">
                    {t('dashboard.mapPopupHosts', { count: row.count })}
                  </span>
                </LeafletTooltip>
              </CircleMarker>
            ))}
          </MapContainer>
        </div>
      )}
    </div>
  );
}
