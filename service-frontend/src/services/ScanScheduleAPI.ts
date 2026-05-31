import type {
  CreateScanScheduleRequest,
  ScanSchedule,
  ScanScheduleListResponse,
  UpdateScanScheduleRequest,
} from '@/types/scanSchedules';

import { apiClient } from './apiClient';

export async function listScanSchedules(
  page = 1,
  limit = 50
): Promise<ScanScheduleListResponse> {
  const response = await apiClient.get<ScanScheduleListResponse>(
    '/v1/scan-schedules',
    { params: { page, limit } }
  );

  return response.data;
}

export async function createScanSchedule(
  payload: CreateScanScheduleRequest
): Promise<ScanSchedule> {
  const response = await apiClient.post<ScanSchedule>(
    '/v1/scan-schedules',
    payload
  );

  return response.data;
}

export async function updateScanSchedule(
  id: number,
  payload: UpdateScanScheduleRequest
): Promise<ScanSchedule> {
  const response = await apiClient.patch<ScanSchedule>(
    `/v1/scan-schedules/${id}`,
    payload
  );

  return response.data;
}

export async function setScanScheduleEnabled(
  id: number,
  enabled: boolean
): Promise<ScanSchedule> {
  const response = await apiClient.patch<ScanSchedule>(
    `/v1/scan-schedules/${id}/enabled`,
    { enabled }
  );

  return response.data;
}

export async function runScanScheduleNow(id: number): Promise<ScanSchedule> {
  const response = await apiClient.post<ScanSchedule>(
    `/v1/scan-schedules/${id}/run`
  );

  return response.data;
}

export async function deleteScanSchedule(id: number): Promise<void> {
  await apiClient.delete(`/v1/scan-schedules/${id}`);
}
