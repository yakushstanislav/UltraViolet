import L from 'leaflet';
import { useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { MapContainer, Marker, Popup, TileLayer, useMap } from 'react-leaflet';

import { resolveCountryCentroid } from '@helpers/dashboardMapCoords';
import { useTheme } from '@/theme/ThemeProvider';
import type { Host } from '@/types/api';


const tileSoft =
  'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';
const tileNight =
  'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';

const PRECISE_ZOOM = 8;
const APPROX_ZOOM = 3;

const pinIcon = L.divIcon({
  className: 'host-map-pin-icon',
  html: `
    <span class="host-map-pin-pulse" aria-hidden="true"></span>
    <svg class="host-map-pin-svg" viewBox="0 0 24 32" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M12 0C5.373 0 0 5.373 0 12c0 8.4 12 20 12 20s12-11.6 12-20C24 5.373 18.627 0 12 0z"/>
      <circle cx="12" cy="12" r="4.5"/>
    </svg>
  `,
  iconSize: [28, 36],
  iconAnchor: [14, 34],
  popupAnchor: [0, -30],
});

type Props = {
  host: Host;
};

type ResolvedLocation = {
  lat: number;
  lng: number;
  zoom: number;
  precise: boolean;
};

function formatCoord(lat: number, lng: number): string {
  const latLabel = `${Math.abs(lat).toFixed(4)}° ${lat >= 0 ? 'N' : 'S'}`;
  const lngLabel = `${Math.abs(lng).toFixed(4)}° ${lng >= 0 ? 'E' : 'W'}`;

  return `${latLabel}, ${lngLabel}`;
}

function resolveLocation(host: Host): ResolvedLocation | null {
  if (
    typeof host.latitude === 'number' &&
    typeof host.longitude === 'number' &&
    Number.isFinite(host.latitude) &&
    Number.isFinite(host.longitude)
  ) {
    return {
      lat: host.latitude,
      lng: host.longitude,
      zoom: PRECISE_ZOOM,
      precise: true,
    };
  }

  if (host.country_code) {
    const centroid = resolveCountryCentroid(host.country_code);

    if (centroid) {
      return {
        lat: centroid.lat,
        lng: centroid.lng,
        zoom: APPROX_ZOOM,
        precise: false,
      };
    }
  }

  return null;
}

function MapSync({
  lat,
  lng,
  zoom,
}: {
  lat: number;
  lng: number;
  zoom: number;
}) {
  const map = useMap();

  useEffect(() => {
    map.setView([lat, lng], zoom, { animate: true });
  }, [lat, lng, map, zoom]);

  useEffect(() => {
    const id = window.setTimeout(() => {
      map.invalidateSize();
    }, 60);

    return () => {
      window.clearTimeout(id);
    };
  }, [map]);

  return null;
}

export function HostLocationMap({ host }: Props) {
  const { t } = useTranslation();
  const { theme } = useTheme();

  const location = useMemo(() => resolveLocation(host), [host]);

  useEffect(() => {
    void import('leaflet/dist/leaflet.css');
  }, []);

  const tileUrl = useMemo(
    () => (theme === 'dark' ? tileNight : tileSoft),
    [theme]
  );

  if (!location) {
    return null;
  }

  const center: L.LatLngExpression = [location.lat, location.lng];

  const locationLabel =
    [host.city, host.country_name].filter(Boolean).join(', ') ||
    host.country_code ||
    t('hostPage.unknownLocation');

  const subtitle = location.precise
    ? locationLabel
    : `${locationLabel}${t('hostPage.approximateSuffix')}`;

  return (
    <div className="host-map-card">
      <div className="host-map-card-header">
        <div className="host-map-card-title">
          <span className="dashboard-panel-title">
            {t('hostPage.locationTitle')}
          </span>
          <span className="host-map-card-subtitle">{subtitle}</span>
        </div>
        {location.precise && (
          <span className="host-map-card-badge cell-mono">
            {formatCoord(location.lat, location.lng)}
          </span>
        )}
        {!location.precise && (
          <span className="host-map-card-badge host-map-card-badge-muted">
            {t('hostPage.countryLevel')}
          </span>
        )}
      </div>
      <div className="host-map-inner">
        <MapContainer
          attributionControl={false}
          center={center}
          className="host-leaflet-map"
          scrollWheelZoom={false}
          zoom={location.zoom}
          zoomControl
        >
          <TileLayer key={tileUrl} url={tileUrl} />
          <MapSync lat={location.lat} lng={location.lng} zoom={location.zoom} />
          <Marker icon={pinIcon} position={center}>
            <Popup>
              <div className="host-map-popup">
                <strong className="cell-mono">{host.ip}</strong>
                <div className="host-map-popup-meta">{locationLabel}</div>
                {host.asn_org && (
                  <div className="host-map-popup-meta">{host.asn_org}</div>
                )}
                {location.precise ? (
                  <div className="host-map-popup-coords cell-mono">
                    {formatCoord(location.lat, location.lng)}
                  </div>
                ) : (
                  <div className="host-map-popup-coords">
                    {t('hostPage.approxCentroid')}
                  </div>
                )}
              </div>
            </Popup>
          </Marker>
        </MapContainer>
      </div>
    </div>
  );
}
