import { useMemo } from 'react';

import {
  LazyCountriesCobeGlobe,
  type CountryCountRow,
} from '@components/maps/LazyCountriesCobeGlobe';
import { buildCountryGlobeMarkers } from '@helpers/dashboardMapHelpers';
import type { SearchHit } from '@/types/api';

type Props = {
  hits: SearchHit[];
  filterCountryCode: string;
};

function aggregateCountries(
  hits: SearchHit[],
  filterCountryCode: string
): CountryCountRow[] {
  const counts = new Map<string, number>();

  for (const hit of hits) {
    if (!hit.country_code) {
      continue;
    }

    const code = hit.country_code.trim().toUpperCase().slice(0, 2);
    if (code.length !== 2) {
      continue;
    }

    counts.set(code, (counts.get(code) ?? 0) + 1);
  }

  const filter = filterCountryCode.trim().toUpperCase();
  if (filter.length === 2 && !counts.has(filter)) {
    counts.set(filter, 1);
  }

  return [...counts.entries()].map(([country_code, count]) => ({
    country_code,
    count,
  }));
}

export function SearchCountriesGlobe({ hits, filterCountryCode }: Props) {
  const rows = useMemo(
    () => aggregateCountries(hits, filterCountryCode),
    [hits, filterCountryCode]
  );

  const markers = useMemo(() => buildCountryGlobeMarkers(rows), [rows]);

  return (
    <LazyCountriesCobeGlobe
      autoRotate
      className="search-globe-canvas-wrap"
      interactive={false}
      markers={markers}
    />
  );
}
