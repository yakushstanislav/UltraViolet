import { createAsyncThunk } from '@reduxjs/toolkit';

import { isAxiosNetworkError } from '@helpers/apiError';
import i18n from '@i18n/i18n';
import { resolveScanCreateErrorMessage } from '@helpers/scanCreateApiError';
import {
  cancelScan,
  createScan,
  listScans,
  type ListScansParams,
} from '@services/ScanAPI';
import type { CreateScanRequest, CreateScanResponse } from '@/types/api';

export const loadScans = createAsyncThunk(
  'scans/load',
  async (params: ListScansParams, { rejectWithValue }) => {
    try {
      return await listScans(params);
    } catch (error: unknown) {
      if (isAxiosNetworkError(error)) {
        return rejectWithValue(i18n.t('common.errors.apiUnreachable'));
      }

      throw error;
    }
  }
);

export const submitScan = createAsyncThunk<
  CreateScanResponse,
  CreateScanRequest,
  { rejectValue: string }
>('scans/submit', async (payload, { rejectWithValue }) => {
  try {
    return await createScan(payload);
  } catch (error: unknown) {
    return rejectWithValue(
      resolveScanCreateErrorMessage(error, 'Failed to create scan')
    );
  }
});

export const stopScan = createAsyncThunk(
  'scans/stop',
  async (scanId: number) => {
    const result = await cancelScan(scanId);

    return { id: scanId, status: result.status };
  }
);
