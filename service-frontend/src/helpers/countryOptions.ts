import raw from '../data/iso3166-slim-2.json';

type IsoRow = {
  name: string;
  'alpha-2': string;
};

export type CountryOption = {
  code: string;
  name: string;
};

const rows = raw as IsoRow[];

export const COUNTRY_OPTIONS: CountryOption[] = rows
  .map((r) => ({
    code: String(r['alpha-2']).toUpperCase(),
    name: r.name,
  }))
  .filter((o) => /^[A-Z]{2}$/.test(o.code))
  .sort((a, b) => a.name.localeCompare(b.name, 'en'));

const byCode = new Map(COUNTRY_OPTIONS.map((o) => [o.code, o]));

export function getCountryLabel(code: string): string {
  const upper = code.toUpperCase();

  return byCode.get(upper)?.name ?? upper;
}
