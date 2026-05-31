import { apiClient } from './apiClient';
import type { RecommendationsResponse } from '@/types/recommendations';

export async function listHostRecommendations(
  ip: string,
  limit = 50,
  signal?: AbortSignal,
): Promise<RecommendationsResponse> {
  const response = await apiClient.get<RecommendationsResponse>(
    `/v1/hosts/${encodeURIComponent(ip)}/risk-recommendations`,
    { params: { limit }, signal },
  );

  return response.data;
}
