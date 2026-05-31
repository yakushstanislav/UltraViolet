import type { RelatedHostsResponse } from '@/types/hosts';

import { apiClient } from './apiClient';

export async function getRelatedHosts(
  ip: string,
  page: number,
  limit: number,
  signal?: AbortSignal
): Promise<RelatedHostsResponse> {
  const response = await apiClient.get<RelatedHostsResponse>(
    `/v1/hosts/${encodeURIComponent(ip)}/related`,
    { params: { page, limit }, signal }
  );

  return response.data;
}
