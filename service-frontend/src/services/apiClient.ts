import axios, {
  type AxiosError,
  type AxiosInstance,
  type AxiosRequestConfig,
  type InternalAxiosRequestConfig,
} from 'axios';
import { toast } from 'sonner';

import i18n from '@i18n/i18n';

import {
  clearAuthTokens,
  getAccessToken,
  getAPIURL,
  getRefreshToken,
  setAccessToken,
  setRefreshToken,
} from '@storage/accessToken';
import { emitForbidden, emitUnauthorized } from './authEvents';
import { realtime } from './realtimeClient';

export type InternalRequestFlags = {
  skipAuthRefresh?: boolean;
  _retry?: boolean;
};

export type AppRequestConfig = AxiosRequestConfig & InternalRequestFlags;

type FlaggedConfig = InternalAxiosRequestConfig & InternalRequestFlags;

function createApiClient(): AxiosInstance {
  const client = axios.create({
    timeout: 15000,
  });

  let refreshInFlight: Promise<void> | null = null;
  let unauthorizedSignalled = false;
  let lastForbiddenAt = 0;

  function signalUnauthorized(): void {
    if (unauthorizedSignalled) {
      return;
    }

    unauthorizedSignalled = true;
    clearAuthTokens();
    toast.error(i18n.t('auth.errors.sessionExpired'));
    emitUnauthorized();
  }

  async function refreshTokens(): Promise<void> {
    const refreshToken = getRefreshToken();
    if (refreshToken === '') {
      throw new Error('no refresh token');
    }

    const refreshResponse = await client.post<{
      access_token: string;
      refresh_token: string;
    }>('/v1/auth/refresh', { refresh_token: refreshToken }, {
      skipAuthRefresh: true,
    } as AppRequestConfig);

    setAccessToken(refreshResponse.data.access_token);
    setRefreshToken(refreshResponse.data.refresh_token);
    realtime.refresh(refreshResponse.data.access_token);
  }

  client.interceptors.request.use((config) => {
    config.baseURL = getAPIURL();

    const token = getAccessToken();
    if (token !== '') {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  });

  client.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const status = error.response?.status;
      const originalRequest = error.config as FlaggedConfig | undefined;

      if (
        status === 401 &&
        originalRequest &&
        !originalRequest.skipAuthRefresh &&
        !originalRequest._retry
      ) {
        const refreshToken = getRefreshToken();
        if (refreshToken !== '') {
          originalRequest._retry = true;

          try {
            if (refreshInFlight === null) {
              unauthorizedSignalled = false;
              refreshInFlight = refreshTokens().finally(() => {
                refreshInFlight = null;
              });
            }

            await refreshInFlight;
          } catch {
            signalUnauthorized();
            return Promise.reject(error);
          }

          unauthorizedSignalled = false;
          return client(originalRequest);
        }

        signalUnauthorized();
      } else if (status === 403 && !originalRequest?.skipAuthRefresh) {
        const now = Date.now();
        if (now - lastForbiddenAt > 2000) {
          lastForbiddenAt = now;
          toast.error(i18n.t('auth.errors.accessDeniedRole'));
          emitForbidden();
        }
      }

      return Promise.reject(error);
    }
  );

  return client;
}

export const apiClient: AxiosInstance = createApiClient();
