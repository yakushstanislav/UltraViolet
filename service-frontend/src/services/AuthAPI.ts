import { apiClient, type AppRequestConfig } from './apiClient';
import type {
  AuthTokenResponse,
  LoginRequest,
  MeResponse,
  RefreshRequest,
} from '@/types/api';

const noRefresh: AppRequestConfig = { skipAuthRefresh: true };

export async function getMe(): Promise<MeResponse> {
  const response = await apiClient.get<MeResponse>('/v1/me', noRefresh);
  return response.data;
}

export async function login(payload: LoginRequest): Promise<AuthTokenResponse> {
  const response = await apiClient.post<AuthTokenResponse>(
    '/v1/auth/login',
    payload,
    noRefresh
  );
  return response.data;
}

export async function refresh(
  payload: RefreshRequest
): Promise<AuthTokenResponse> {
  const response = await apiClient.post<AuthTokenResponse>(
    '/v1/auth/refresh',
    payload,
    noRefresh
  );
  return response.data;
}

export async function logout(payload: RefreshRequest): Promise<void> {
  await apiClient.post('/v1/auth/logout', payload, noRefresh);
}
