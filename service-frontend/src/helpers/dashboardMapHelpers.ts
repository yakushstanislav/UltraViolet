import type { Marker } from 'cobe';
import type { TFunction } from 'i18next';

import type { CountryCountRow } from '@components/CountriesCobeGlobe';
import { resolveCountryCentroid } from '@helpers/dashboardMapCoords';
import { cobeMarkerSize, leafletRadius } from '@helpers/markerRadius';
import type {
  DashboardMapCountryRow,
  DashboardMapPointRow,
  DashboardMapPointsSource,
} from '@/types/api';

export type PlottedMapCountry = {
  country_code: string;
  count: number;
  lat: number;
  lng: number;
  radius: number;
};

export type DashboardMapEmptyKind = 'no_country' | 'no_centroid';

const countryMarkerLimit = 48;
const hostMarkerBaseSize = 0.014;
const hostMarkerHighlightSize = 0.024;
const hostMarkerDimSize = 0.009;
export const hostGlobeLimit = 800;

export function computeDashboardMapTotals(countries: DashboardMapCountryRow[]): {
  countryCount: number;
  hostCount: number;
} {
  return {
    countryCount: countries.length,
    hostCount: countries.reduce((sum, row) => sum + row.count, 0),
  };
}

export function formatDashboardMapSubtitle(
  countries: DashboardMapCountryRow[],
  t: TFunction
): string | null {
  if (countries.length === 0) {
    return null;
  }

  const { countryCount, hostCount } = computeDashboardMapTotals(countries);

  return t('dashboard.mapSubtitle', {
    countries: countryCount.toLocaleString(),
    hosts: hostCount.toLocaleString(),
  });
}

export type DashboardGlobeStatsLabels = {
  base: string;
  globe: string;
};

export function formatDashboardGlobeStats(
  countries: DashboardMapCountryRow[],
  plottedCount: number,
  onGlobeCount: number,
  t: TFunction
): DashboardGlobeStatsLabels | null {
  if (countries.length === 0 && plottedCount === 0 && onGlobeCount === 0) {
    return null;
  }

  const { countryCount, hostCount } = computeDashboardMapTotals(countries);

  return {
    base: t('dashboard.mapGlobeStatsBase', {
      countries: countryCount.toLocaleString(),
      hosts: hostCount.toLocaleString(),
    }),
    globe: t('dashboard.mapGlobeStatsGlobe', {
      plotted: plottedCount.toLocaleString(),
      onGlobe: onGlobeCount.toLocaleString(),
    }),
  };
}

export function plotDashboardMapCountries(
  countries: DashboardMapCountryRow[]
): PlottedMapCountry[] {
  const resolved: PlottedMapCountry[] = [];

  for (const row of countries) {
    const centroid = resolveCountryCentroid(row.country_code);
    if (!centroid) {
      continue;
    }

    resolved.push({
      country_code: row.country_code,
      count: row.count,
      lat: centroid.lat,
      lng: centroid.lng,
      radius: 8,
    });
  }

  const maxCount = resolved.reduce((max, row) => Math.max(max, row.count), 0);

  for (const row of resolved) {
    row.radius = leafletRadius(row.count, maxCount);
  }

  return resolved;
}

export function plottedToCountryCountRows(
  plotted: PlottedMapCountry[]
): CountryCountRow[] {
  return plotted.map((row) => ({
    country_code: row.country_code,
    count: row.count,
  }));
}

export function resolveDashboardMapEmptyKind(
  loading: boolean,
  error: string | null,
  countries: DashboardMapCountryRow[],
  plotted: PlottedMapCountry[],
  points: DashboardMapPointRow[] = []
): DashboardMapEmptyKind | null {
  if (loading || error) {
    return null;
  }

  if (countries.length === 0 && points.length === 0) {
    return 'no_country';
  }

  if (plotted.length === 0 && points.length === 0) {
    return 'no_centroid';
  }

  return null;
}

export function buildCountryGlobeMarkers(
  rows: CountryCountRow[],
  highlightedCountry?: string | null,
  maxMarkers: number = countryMarkerLimit
): Marker[] {
  const highlight = highlightedCountry?.trim().toUpperCase().slice(0, 2) ?? '';
  const sorted = [...rows].sort((a, b) => b.count - a.count);
  const top = sorted.slice(0, maxMarkers);
  const maxCount = top.reduce((m, row) => Math.max(m, row.count), 0);

  const markers: Marker[] = [];

  for (const row of top) {
    const pos = resolveCountryCentroid(row.country_code);
    if (!pos) {
      continue;
    }

    const code = row.country_code.trim().toUpperCase().slice(0, 2);
    const isHighlight = highlight.length === 2 && code === highlight;
    const baseSize = cobeMarkerSize(row.count, maxCount);

    markers.push({
      location: [pos.lat, pos.lng],
      size: isHighlight ? baseSize * 1.45 : highlight ? baseSize * 0.72 : baseSize,
      id: code,
    });
  }

  return markers;
}

function jitterCentroid(
  lat: number,
  lng: number,
  countryCode: string,
  index: number
): { lat: number; lng: number } {
  const code = countryCode.trim().toUpperCase().slice(0, 2);
  let seed = 0;

  for (let i = 0; i < code.length; i += 1) {
    seed = seed * 31 + code.charCodeAt(i);
  }

  const angle = ((seed * 2654435761 + index * 9747) % 6283) / 1000;
  const radius = 0.12 + (index % 9) * 0.07;
  const dlat = radius * Math.cos(angle) * 0.65;
  const dlng =
    (radius * Math.sin(angle)) / Math.max(0.35, Math.cos((lat * Math.PI) / 180));

  return {
    lat: Math.max(-90, Math.min(90, lat + dlat)),
    lng: Math.max(-180, Math.min(180, lng + dlng)),
  };
}

export function buildCentroidFallbackPointsFromPlotted(
  plotted: PlottedMapCountry[],
  limit: number
): DashboardMapPointRow[] {
  if (limit <= 0 || plotted.length === 0) {
    return [];
  }

  const weighted = plotted
    .filter((row) => row.count > 0)
    .sort((a, b) => b.count - a.count);

  const totalHosts = weighted.reduce((sum, row) => sum + row.count, 0);
  if (totalHosts === 0) {
    return [];
  }

  const out: DashboardMapPointRow[] = [];
  let remaining = limit;

  for (const row of weighted) {
    if (remaining <= 0) {
      break;
    }

    let share = Math.floor((row.count * limit) / totalHosts);
    if (share < 1) {
      share = 1;
    }

    if (share > remaining) {
      share = remaining;
    }

    if (share > row.count) {
      share = row.count;
    }

    for (let i = 0; i < share; i += 1) {
      const { lat, lng } = jitterCentroid(row.lat, row.lng, row.country_code, i);

      out.push({
        latitude: lat,
        longitude: lng,
        country_code: row.country_code,
      });
    }

    remaining -= share;
  }

  return out;
}

export function resolveGlobeHostPoints(
  apiPoints: DashboardMapPointRow[],
  plotted: PlottedMapCountry[],
  apiSource?: DashboardMapPointsSource
): { points: DashboardMapPointRow[]; source: DashboardMapPointsSource } {
  if (apiPoints.length > 0) {
    return {
      points: apiPoints,
      source: apiSource === 'country_centroid' ? 'country_centroid' : 'geo',
    };
  }

  const fallback = buildCentroidFallbackPointsFromPlotted(plotted, hostGlobeLimit);
  if (fallback.length > 0) {
    return { points: fallback, source: 'country_centroid' };
  }

  return { points: [], source: 'geo' };
}

export function subsampleMapPoints(
  points: DashboardMapPointRow[],
  max: number
): DashboardMapPointRow[] {
  if (points.length <= max) {
    return points;
  }

  const step = points.length / max;
  const sampled: DashboardMapPointRow[] = [];

  for (let i = 0; i < max; i += 1) {
    const index = Math.min(points.length - 1, Math.floor(i * step));
    const point = points[index];
    if (point) {
      sampled.push(point);
    }
  }

  return sampled;
}

export function buildHostGlobeMarkers(
  points: DashboardMapPointRow[],
  highlightedCountry?: string | null
): Marker[] {
  const highlight = highlightedCountry?.trim().toUpperCase().slice(0, 2) ?? '';
  const markers: Marker[] = [];

  for (const point of points) {
    const code = point.country_code?.trim().toUpperCase().slice(0, 2) ?? '';
    const isHighlight = highlight.length === 2 && code === highlight;
    const isDimmed = highlight.length === 2 && code !== highlight && code.length === 2;

    markers.push({
      location: [point.latitude, point.longitude],
      size: isHighlight
        ? hostMarkerHighlightSize
        : isDimmed
          ? hostMarkerDimSize
          : hostMarkerBaseSize,
      id: code || undefined,
    });
  }

  return markers;
}
