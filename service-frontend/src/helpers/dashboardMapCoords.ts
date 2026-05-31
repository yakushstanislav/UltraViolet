import { z } from 'zod';

import countryCentroids from '../data/countryCentroids.json';

const centroidSchema = z.tuple([z.number(), z.number()]);
const centroidMapSchema = z.record(z.string(), centroidSchema);

type CentroidMap = z.infer<typeof centroidMapSchema>;

const CENTROIDS: CentroidMap = centroidMapSchema.parse(countryCentroids);

const ALPHA2_RE = /^[A-Z]{2}$/;

/** Normalizes API country_code to ISO 3166-1 alpha-2 for centroid lookup. */
export function normalizeCountryMapCode(raw: string): string {
  const s = raw.trim().toUpperCase();

  if (!s) {
    return '';
  }

  if (s === 'UK') {
    return 'GB';
  }

  const candidate = s.length > 2 ? s.slice(0, 2) : s;

  return ALPHA2_RE.test(candidate) ? candidate : '';
}

/** Returns reference map coordinates for a country code, or null if unknown. */
export function resolveCountryCentroid(
  countryCode: string
): { lat: number; lng: number } | null {
  const code = normalizeCountryMapCode(countryCode);
  if (!code) {
    return null;
  }

  const pair = CENTROIDS[code];
  if (!pair) {
    return null;
  }

  return { lat: pair[0], lng: pair[1] };
}
