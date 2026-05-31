import { apiClient } from './apiClient';
import type { SearchResponse } from '@/types/api';

/** Wire params for GET /v1/search — field order matches searchFormHelpers.SEARCH_FIELD_KEYS. */
export type SearchParams = {
  q?: string;
  q_mode?: string;
  port?: string;
  port_from?: number;
  port_to?: number;
  country?: string;
  asn?: string;
  protocol?: string;
  tls_issuer?: string;
  tls_fingerprint?: string;
  tls_subject?: string;
  tls_san?: string;
  ssh?: string;
  ssh_fingerprint?: string;
  smtp?: string;
  dns?: string;
  risk_score_min?: number;
  risk_score_max?: number;
  last_seen_from?: string;
  last_seen_to?: string;
  has_cve?: string;
  cve_severity?: string;
  cve_id?: string;
  cve_text?: string;
  confidence_gte?: number;
  sort?: string;
  page?: number;
  limit?: number;
};

export async function search(
  params: SearchParams,
  signal?: AbortSignal
): Promise<SearchResponse> {
  const response = await apiClient.get<SearchResponse>('/v1/search', {
    params,
    signal,
  });

  return response.data;
}
