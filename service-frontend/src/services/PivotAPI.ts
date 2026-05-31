import type { PivotResponse } from '@/types/pivot';

import { apiClient } from './apiClient';

export async function getPivot(
  kind: string,
  value: string,
  limit?: number,
  signal?: AbortSignal
): Promise<PivotResponse> {
  const response = await apiClient.get<PivotResponse>(
    `/v1/pivot/${encodeURIComponent(kind)}/${encodeURIComponent(value)}`,
    { params: limit ? { limit } : undefined, signal }
  );

  return response.data;
}
