import { apiClient } from './apiClient';
import type { AttackPathView } from '@/types/attackPath';

export async function getAttackPath(
  ip: string,
  signal?: AbortSignal,
): Promise<AttackPathView> {
  const response = await apiClient.get<AttackPathView>(
    `/v1/attack-paths/${encodeURIComponent(ip)}`,
    { signal },
  );

  return response.data;
}
