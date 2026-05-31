import type { Marker } from 'cobe';
import { useMemo } from 'react';

import type { CobeGlobeFocus } from '@/hooks/useCobeGlobe';
import { useCobeGlobe } from '@/hooks/useCobeGlobe';
import { useTheme } from '@/theme/ThemeProvider';

export type CountryCountRow = {
  country_code: string;
  count: number;
};

type Props = {
  markers: Marker[];
  className?: string;
  interactive?: boolean;
  mapSamples?: number;
  autoRotate?: boolean;
  focusLocation?: CobeGlobeFocus | null;
};

const baseWrapClass = 'countries-cobe-globe-wrap';

export function CountriesCobeGlobe({
  markers,
  className,
  interactive = true,
  mapSamples,
  autoRotate = true,
  focusLocation = null,
}: Props) {
  const { theme } = useTheme();

  const wrapClass = useMemo(() => {
    const parts = [baseWrapClass, className];
    if (interactive) {
      parts.push('dashboard-globe-canvas-wrap--interactive');
    }

    return parts.filter(Boolean).join(' ');
  }, [className, interactive]);

  const { wrapRef } = useCobeGlobe({
    markers,
    theme,
    interactive,
    mapSamples,
    autoRotate,
    focusLocation,
  });

  return (
    <div aria-hidden className={wrapClass} ref={wrapRef} />
  );
}
