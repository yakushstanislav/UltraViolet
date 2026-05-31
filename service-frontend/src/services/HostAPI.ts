import type {
  Host,
  ONVIFCommandRequest,
  ONVIFCommandResponse,
  ONVIFLabCredentialProbeRequest,
  ONVIFLabCredentialProbeResponse,
  ONVIFRTSPSnapshotRequest,
  RTSPSnapshotRequest,
  RTSPSnapshotResponse,
} from '@/types/hosts';
import type { HostRiskExplainResponse } from '@/types/pivot';
import type { RiskHistoryResponse, ServiceRiskExplain } from '@/types/risk';

import { apiClient } from './apiClient';

export type HostServicesParams = {
  page?: number;
  limit?: number;
};

export async function getHost(
  ip: string,
  params: HostServicesParams,
  signal?: AbortSignal
): Promise<Host> {
  const response = await apiClient.get<Host>(
    `/v1/hosts/${encodeURIComponent(ip)}`,
    { params, signal }
  );

  return response.data;
}

const defaultRTSPSnapshotTimeoutMs = 90_000;

/** Enough for many short ffmpeg attempts when `auto_try_common_paths` is set. */
const autoRTSPSnapshotTimeoutMs = 210_000;

export async function postHostRTSPSnapshot(
  ip: string,
  body: RTSPSnapshotRequest,
  options?: { timeoutMs?: number }
): Promise<RTSPSnapshotResponse> {
  const timeoutMs =
    options?.timeoutMs ??
    (body.auto_try_common_paths === true
      ? autoRTSPSnapshotTimeoutMs
      : defaultRTSPSnapshotTimeoutMs);

  const response = await apiClient.post<Blob>(
    `/v1/hosts/${encodeURIComponent(ip)}/rtsp-snapshot`,
    body,
    { responseType: 'blob', timeout: timeoutMs }
  );

  const headerVal =
    response.headers['x-uv-rtsp-snapshot-path'] ??
    response.headers['X-UV-RTSP-Snapshot-Path'];

  const resolvedPath =
    typeof headerVal === 'string' && headerVal !== '' ? headerVal : undefined;

  return { blob: response.data, resolvedPath };
}

const onvifCommandTimeoutMs = 90_000;

export async function postHostOnvifCommand(
  ip: string,
  body: ONVIFCommandRequest
): Promise<ONVIFCommandResponse> {
  const response = await apiClient.post<ONVIFCommandResponse>(
    `/v1/hosts/${encodeURIComponent(ip)}/onvif-command`,
    body,
    { timeout: onvifCommandTimeoutMs }
  );

  return response.data;
}

const onvifLabProbeTimeoutMs = 600_000;

export async function postHostOnvifLabCredentialProbe(
  ip: string,
  body: ONVIFLabCredentialProbeRequest
): Promise<ONVIFLabCredentialProbeResponse> {
  const response = await apiClient.post<ONVIFLabCredentialProbeResponse>(
    `/v1/hosts/${encodeURIComponent(ip)}/onvif-lab-credential-probe`,
    body,
    { timeout: onvifLabProbeTimeoutMs }
  );

  return response.data;
}

const hostHttpScreenshotTimeoutMs = 30_000;

export async function getHostHttpScreenshot(
  ip: string,
  serviceId: number,
  signal?: AbortSignal
): Promise<Blob> {
  const response = await apiClient.get<Blob>(
    `/v1/hosts/${encodeURIComponent(ip)}/services/${serviceId}/screenshot`,
    { responseType: 'blob', timeout: hostHttpScreenshotTimeoutMs, signal }
  );

  return response.data;
}

const onvifRtspSnapshotTimeoutMs = 120_000;

export async function postHostOnvifRtspSnapshot(
  ip: string,
  body: ONVIFRTSPSnapshotRequest,
  signal?: AbortSignal
): Promise<{ blob: Blob }> {
  const response = await apiClient.post<Blob>(
    `/v1/hosts/${encodeURIComponent(ip)}/onvif-rtsp-snapshot`,
    body,
    { responseType: 'blob', timeout: onvifRtspSnapshotTimeoutMs, signal }
  );

  return { blob: response.data };
}

export async function getHostRiskExplain(
  ip: string,
  signal?: AbortSignal
): Promise<HostRiskExplainResponse> {
  const response = await apiClient.get<HostRiskExplainResponse>(
    `/v1/hosts/${encodeURIComponent(ip)}/risk-explain`,
    { signal }
  );

  return response.data;
}

export async function getServiceRiskExplain(
  serviceId: number,
  signal?: AbortSignal
): Promise<ServiceRiskExplain> {
  const response = await apiClient.get<ServiceRiskExplain>(
    `/v1/services/${serviceId}/risk-explain`,
    { signal }
  );

  return response.data;
}

export type HostRiskHistoryParams = {
  days?: number;
  limit?: number;
};

export async function getHostRiskHistory(
  ip: string,
  params: HostRiskHistoryParams,
  signal?: AbortSignal
): Promise<RiskHistoryResponse> {
  const response = await apiClient.get<RiskHistoryResponse>(
    `/v1/hosts/${encodeURIComponent(ip)}/risk-history`,
    { params, signal }
  );

  return response.data;
}
