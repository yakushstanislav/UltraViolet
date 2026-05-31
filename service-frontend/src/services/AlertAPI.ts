import type {
  AlertEventsResponse,
  AlertListResponse,
  CreateAlertRequest,
} from '@/types/alerts';

import { apiClient } from './apiClient';

export async function listAlerts(
  page = 1,
  limit = 100
): Promise<AlertListResponse> {
  const response = await apiClient.get<AlertListResponse>('/v1/alerts/all', {
    params: { page, limit },
  });

  return response.data;
}

export async function createAlert(
  body: CreateAlertRequest
): Promise<{ id: number }> {
  const response = await apiClient.post<{ id: number }>('/v1/alerts', body);

  return response.data;
}

export async function deleteAlert(id: number): Promise<void> {
  await apiClient.delete(`/v1/alerts/${id}`);
}

export async function setAlertEnabled(
  id: number,
  enabled: boolean
): Promise<void> {
  await apiClient.patch(`/v1/alerts/${id}/enabled`, { enabled });
}

export async function listAlertEvents(
  page = 1,
  limit = 50
): Promise<AlertEventsResponse> {
  const response = await apiClient.get<AlertEventsResponse>(
    '/v1/alerts/events',
    { params: { page, limit } }
  );

  return response.data;
}
