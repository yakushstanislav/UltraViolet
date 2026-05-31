import { lazy, Suspense, type ComponentProps } from 'react';

import type { CountriesCobeGlobe } from '@components/CountriesCobeGlobe';

export type { CountryCountRow } from '@components/CountriesCobeGlobe';

const CountriesCobeGlobeLazy = lazy(() =>
  import('@components/CountriesCobeGlobe').then((module) => ({
    default: module.CountriesCobeGlobe,
  }))
);

type Props = ComponentProps<typeof CountriesCobeGlobe>;

function CountriesCobeGlobeFallback({ className }: Pick<Props, 'className'>) {
  return (
    <div
      aria-busy="true"
      className={['countries-cobe-globe-wrap', className, 'dashboard-map-skeleton']
        .filter(Boolean)
        .join(' ')}
    />
  );
}

export function LazyCountriesCobeGlobe(props: Props) {
  return (
    <Suspense fallback={<CountriesCobeGlobeFallback className={props.className} />}>
      <CountriesCobeGlobeLazy {...props} />
    </Suspense>
  );
}
