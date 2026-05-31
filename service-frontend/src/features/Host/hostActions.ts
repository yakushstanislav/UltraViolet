import { createAsyncThunk } from '@reduxjs/toolkit';

import { getHost } from '@services/HostAPI';

type LoadHostPayload = {
  ip: string;
  page: number;
  limit: number;
};

export const loadHost = createAsyncThunk(
  'host/load',
  (payload: LoadHostPayload, { signal }) =>
    getHost(payload.ip, { page: payload.page, limit: payload.limit }, signal)
);
