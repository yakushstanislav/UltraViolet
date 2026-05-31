import type { SearchQuery } from '@/types/common';
import type {
  RunSavedSearchResponse,
  SavedSearchListResponse,
} from '@/types/savedSearches';

import { apiClient } from './apiClient';

export async function listSavedSearches(
  page = 1,
  limit = 50
): Promise<SavedSearchListResponse> {
  const response = await apiClient.get<SavedSearchListResponse>(
    '/v1/saved-searches',
    { params: { page, limit } }
  );

  return response.data;
}

export async function createSavedSearch(
  name: string,
  query: SearchQuery
): Promise<{ id: number }> {
  const response = await apiClient.post<{ id: number }>('/v1/saved-searches', {
    name,
    query,
  });

  return response.data;
}

export async function deleteSavedSearch(id: number): Promise<void> {
  await apiClient.delete(`/v1/saved-searches/${id}`);
}

export async function runSavedSearch(
  id: number
): Promise<RunSavedSearchResponse> {
  const response = await apiClient.post<RunSavedSearchResponse>(
    `/v1/saved-searches/${id}/run`
  );

  return response.data;
}
