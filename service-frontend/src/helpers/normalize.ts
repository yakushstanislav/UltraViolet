export function normalizeText(value: unknown): string {
  return String(value ?? '').trim();
}

export function normalizeUpperText(value: unknown): string {
  return normalizeText(value).toUpperCase();
}

export function normalizeToken(value: string): string {
  return value.trim();
}

export function normalizeURL(value: string): string {
  return value.trim().replace(/\/+$/, '');
}
