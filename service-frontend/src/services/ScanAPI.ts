import type {
  CancelScanResponse,
  CreateScanRequest,
  CreateScanResponse,
  PauseScanResponse,
  RestartScanResponse,
  ResumeScanResponse,
  Scan,
  ScanDeltaEventsResponse,
  ScanDeltaSummary,
  ScanListResponse,
} from '@/types/scans';

import { apiClient } from './apiClient';

export type ListScansParams = {
  page?: number;
  limit?: number;
  sort?: 'id' | 'created_at' | 'status';
  order?: 'asc' | 'desc';
};

export async function listScans(
  params: ListScansParams
): Promise<ScanListResponse> {
  const response = await apiClient.get<ScanListResponse>('/v1/scans', {
    params: {
      page: params.page,
      limit: params.limit,
      sort: params.sort,
      order: params.order,
    },
  });

  return response.data;
}

export async function getScan(
  scanId: number,
  signal?: AbortSignal
): Promise<Scan> {
  const response = await apiClient.get<Scan>(`/v1/scans/${scanId}`, { signal });

  return response.data;
}

export async function createScan(
  payload: CreateScanRequest
): Promise<CreateScanResponse> {
  const response = await apiClient.post<CreateScanResponse>(
    '/v1/scans',
    payload
  );

  return response.data;
}

export async function cancelScan(scanId: number): Promise<CancelScanResponse> {
  const response = await apiClient.post<CancelScanResponse>(
    `/v1/scans/${scanId}/cancel`
  );

  return response.data;
}

export async function pauseScan(scanId: number): Promise<PauseScanResponse> {
  const response = await apiClient.post<PauseScanResponse>(
    `/v1/scans/${scanId}/pause`
  );

  return response.data;
}

export async function resumeScan(scanId: number): Promise<ResumeScanResponse> {
  const response = await apiClient.post<ResumeScanResponse>(
    `/v1/scans/${scanId}/resume`
  );

  return response.data;
}

export async function restartScan(
  scanId: number
): Promise<RestartScanResponse> {
  const response = await apiClient.post<RestartScanResponse>(
    `/v1/scans/${scanId}/restart`
  );

  return response.data;
}

export async function getScanDelta(
  scanId: number,
  signal?: AbortSignal
): Promise<ScanDeltaSummary> {
  const response = await apiClient.get<ScanDeltaSummary>(
    `/v1/scans/${scanId}/delta`,
    { signal }
  );

  return response.data;
}

export async function getScanDeltaEvents(
  scanId: number,
  page = 1,
  limit = 25,
  signal?: AbortSignal
): Promise<ScanDeltaEventsResponse> {
  const response = await apiClient.get<ScanDeltaEventsResponse>(
    `/v1/scans/${scanId}/delta/events`,
    { params: { page, limit }, signal }
  );

  return response.data;
}
