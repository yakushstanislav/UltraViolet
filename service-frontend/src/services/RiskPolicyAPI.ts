import { apiClient } from './apiClient';
import type { RiskPolicy } from '@/types/riskPolicy';

export async function getRiskPolicy(): Promise<RiskPolicy> {
  const response = await apiClient.get<RiskPolicy>('/v1/risk/policy');

  return response.data;
}

export async function updateRiskPolicy(body: RiskPolicy): Promise<RiskPolicy> {
  const response = await apiClient.patch<RiskPolicy>('/v1/risk/policy', body);

  return response.data;
}
