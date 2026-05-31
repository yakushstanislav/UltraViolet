import { normalizeToken, normalizeURL } from '@helpers/normalize';

const tokenKey = 'uv_api_token';
const refreshTokenKey = 'uv_refresh_token';
const apiURLKey = 'uv_api_url';
const realtimeURLKey = 'uv_realtime_url';

function safeRead(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeWrite(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* localStorage unavailable or quota exceeded; ignore */
  }
}

function safeRemove(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    /* localStorage unavailable; ignore */
  }
}

export function getAccessToken(): string {
  return safeRead(tokenKey) ?? '';
}

export function setAccessToken(token: string): void {
  const normalized = normalizeToken(token);
  if (normalized === '') {
    safeRemove(tokenKey);

    return;
  }

  safeWrite(tokenKey, normalized);
}

export function getRefreshToken(): string {
  return safeRead(refreshTokenKey) ?? '';
}

export function setRefreshToken(token: string): void {
  const normalized = normalizeToken(token);
  if (normalized === '') {
    safeRemove(refreshTokenKey);

    return;
  }

  safeWrite(refreshTokenKey, normalized);
}

export function clearAuthTokens(): void {
  safeRemove(tokenKey);
  safeRemove(refreshTokenKey);
}

export function getAPIURL(): string {
  const stored = safeRead(apiURLKey);
  if (stored != null && stored !== '') {
    return stored;
  }

  const fromEnv = import.meta.env.VITE_API_URL;
  if (typeof fromEnv === 'string' && fromEnv !== '') {
    return fromEnv;
  }

  // Vite dev proxies /api → uv-api (see vite.config.ts); keeps REST and WS same-origin.
  if (import.meta.env.DEV) {
    return '/api';
  }

  return joinBase('api');
}

export function setAPIURL(url: string): void {
  const value = normalizeURL(url);

  if (value === '') {
    safeRemove(apiURLKey);

    return;
  }

  safeWrite(apiURLKey, value);
}

export function getRealtimeURL(): string {
  const stored = safeRead(realtimeURLKey);
  if (stored != null && stored !== '') {
    return stored;
  }

  const fromEnv = import.meta.env.VITE_REALTIME_URL;
  if (typeof fromEnv === 'string' && fromEnv !== '') {
    return fromEnv;
  }

  if (import.meta.env.DEV) {
    return '/realtime';
  }

  return joinBase('realtime');
}

// joinBase concatenates Vite's BASE_URL with a relative subpath so the SPA
// can be hosted under "/" or "/ultraviolet/" without rebuilding the API
// client. BASE_URL is injected by Vite from base: in vite.config.ts.
function joinBase(suffix: string): string {
  const base = (import.meta.env.BASE_URL ?? '/').replace(/\/$/, '');

  return `${base}/${suffix}`;
}

export function setRealtimeURL(url: string): void {
  const value = normalizeURL(url);

  if (value === '') {
    safeRemove(realtimeURLKey);

    return;
  }

  safeWrite(realtimeURLKey, value);
}
