import { apiClient } from './apiClient';

export type VersionResponse = {
  version: string;
  commit: string;
  demo_mode: boolean;
};

export async function getVersion(): Promise<VersionResponse> {
  const response = await apiClient.get<VersionResponse>('/v1/version');
  return response.data;
}
