import type { AuditListParams, AuditListResponse } from '@/types/audit';

import { apiClient } from './apiClient';

export async function listAuditEvents(
  params: AuditListParams,
  signal?: AbortSignal
): Promise<AuditListResponse> {
  const query: Record<string, string | number> = {
    page: params.page,
    limit: params.limit,
  };

  if (params.method) {
    query.method = params.method;
  }

  if (params.status_family) {
    query.status_family = params.status_family;
  }

  if (params.q) {
    query.q = params.q;
  }

  if (params.user_id !== undefined) {
    query.user_id = params.user_id;
  }

  if (params.since) {
    query.since = params.since;
  }

  if (params.until) {
    query.until = params.until;
  }

  const response = await apiClient.get<AuditListResponse>('/v1/audit', {
    params: query,
    signal,
  });

  return response.data;
}
