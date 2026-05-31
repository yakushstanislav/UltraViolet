import type {
  DashboardMapResponse,
  DashboardRiskResponse,
  DashboardScansSummaryResponse,
  DashboardStats,
  DashboardTopResponse,
  DashboardTrendsBucket,
  DashboardTrendsRange,
  DashboardTrendsResponse,
} from '@/types/api';

import { apiClient } from './apiClient';

export async function getDashboardStats(): Promise<DashboardStats> {
  const response = await apiClient.get<DashboardStats>('/v1/dashboard');

  return response.data;
}

export async function getDashboardMap(
  signal?: AbortSignal
): Promise<DashboardMapResponse> {
  const response = await apiClient.get<DashboardMapResponse>(
    '/v1/dashboard/map',
    { signal }
  );

  return response.data;
}

export async function getDashboardTrends(params?: {
  range?: DashboardTrendsRange;
  bucket?: DashboardTrendsBucket;
}): Promise<DashboardTrendsResponse> {
  const response = await apiClient.get<DashboardTrendsResponse>(
    '/v1/dashboard/trends',
    { params }
  );

  return response.data;
}

export async function getDashboardTop(params?: {
  limit?: number;
}): Promise<DashboardTopResponse> {
  const response = await apiClient.get<DashboardTopResponse>(
    '/v1/dashboard/top',
    { params }
  );

  return response.data;
}

export async function getDashboardRisk(): Promise<DashboardRiskResponse> {
  const response =
    await apiClient.get<DashboardRiskResponse>('/v1/dashboard/risk');

  return response.data;
}

export async function getDashboardScansSummary(): Promise<DashboardScansSummaryResponse> {
  const response = await apiClient.get<DashboardScansSummaryResponse>(
    '/v1/dashboard/scans/summary'
  );

  return response.data;
}
