import type { CVESyncStatusResponse } from '@/types/api';

import { apiClient } from './apiClient';

export async function getCVESyncStatus(
  signal?: AbortSignal
): Promise<CVESyncStatusResponse> {
  const response = await apiClient.get<CVESyncStatusResponse>(
    '/v1/cve/sync-status',
    { signal }
  );

  return response.data;
}
