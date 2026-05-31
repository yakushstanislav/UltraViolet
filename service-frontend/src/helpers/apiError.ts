import axios from 'axios';

import i18n from '@i18n/i18n';

const ERROR_CODE_I18N: Record<string, string> = {
  demo_mode_restricted: 'common.errors.demo_mode_restricted',
};

export function extractApiErrorMessage(
  error: unknown,
  fallback: string
): string {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data;
    if (payload && typeof payload === 'object') {
      const record = payload as { error?: unknown; message?: unknown };
      if (typeof record.error === 'string' && record.error !== '') {
        const i18nKey = ERROR_CODE_I18N[record.error];
        if (i18nKey) {
          return i18n.t(i18nKey);
        }
        return record.error;
      }
      if (typeof record.message === 'string' && record.message !== '') {
        return record.message;
      }
    }

    return fallback;
  }

  if (typeof error === 'string' && error !== '') {
    return error;
  }

  if (error && typeof error === 'object') {
    const record = error as { message?: unknown; error?: unknown };
    if (typeof record.message === 'string' && record.message !== '') {
      return record.message;
    }
    if (typeof record.error === 'string' && record.error !== '') {
      return record.error;
    }
  }

  return fallback;
}

/** Axios could not reach the server (proxy down, ECONNREFUSED, offline). */
export function isAxiosNetworkError(error: unknown): boolean {
  return axios.isAxiosError(error) && error.code === 'ERR_NETWORK';
}

type DomainErrorOptions = {
  reasons: readonly string[];
  i18nPrefix: string;
  fallback: string;
};

export function extractDomainErrorMessage(
  error: unknown,
  { reasons, i18nPrefix, fallback }: DomainErrorOptions
): string {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data;
    if (payload && typeof payload === 'object') {
      const reason = (payload as { reason?: unknown }).reason;
      if (typeof reason === 'string' && reason !== '') {
        if ((reasons as readonly string[]).includes(reason)) {
          return i18n.t(`${i18nPrefix}.${reason}`);
        }

        return fallback;
      }
    }
  }

  return extractApiErrorMessage(error, fallback);
}
