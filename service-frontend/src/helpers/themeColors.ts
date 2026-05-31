export type RGBTriplet = [number, number, number];

const DEFAULT_ACCENT_DARK: RGBTriplet = [0.13, 0.83, 0.93];
const DEFAULT_ACCENT_LIGHT: RGBTriplet = [0.03, 0.57, 0.7];

function parseHex(hex: string): RGBTriplet | null {
  const trimmed = hex.trim().replace(/^#/, '');
  const value =
    trimmed.length === 3
      ? trimmed
          .split('')
          .map((c) => c + c)
          .join('')
      : trimmed;

  if (value.length !== 6) {
    return null;
  }

  const r = Number.parseInt(value.slice(0, 2), 16);
  const g = Number.parseInt(value.slice(2, 4), 16);
  const b = Number.parseInt(value.slice(4, 6), 16);

  if (!Number.isFinite(r) || !Number.isFinite(g) || !Number.isFinite(b)) {
    return null;
  }

  return [r / 255, g / 255, b / 255];
}

function parseRgb(value: string): RGBTriplet | null {
  const match = value.match(
    /rgba?\(\s*(\d+(?:\.\d+)?)[,\s]+(\d+(?:\.\d+)?)[,\s]+(\d+(?:\.\d+)?)/i
  );

  if (!match) {
    return null;
  }

  const [, rRaw, gRaw, bRaw] = match;
  if (rRaw === undefined || gRaw === undefined || bRaw === undefined) {
    return null;
  }

  const r = Number.parseFloat(rRaw);
  const g = Number.parseFloat(gRaw);
  const b = Number.parseFloat(bRaw);

  return [r / 255, g / 255, b / 255];
}

export function readCssColorTriplet(
  varName: string,
  fallback: RGBTriplet
): RGBTriplet {
  if (typeof window === 'undefined') {
    return fallback;
  }

  const raw = getComputedStyle(document.documentElement)
    .getPropertyValue(varName)
    .trim();

  if (raw === '') {
    return fallback;
  }

  if (raw.startsWith('#')) {
    return parseHex(raw) ?? fallback;
  }

  if (raw.toLowerCase().startsWith('rgb')) {
    return parseRgb(raw) ?? fallback;
  }

  return fallback;
}

export function readCssColorString(varName: string, fallback: string): string {
  if (typeof window === 'undefined') {
    return fallback;
  }

  const raw = getComputedStyle(document.documentElement)
    .getPropertyValue(varName)
    .trim();

  return raw === '' ? fallback : raw;
}

export function defaultAccentTriplet(theme: 'light' | 'dark'): RGBTriplet {
  return theme === 'dark' ? DEFAULT_ACCENT_DARK : DEFAULT_ACCENT_LIGHT;
}
