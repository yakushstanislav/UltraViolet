import { createSlice } from '@reduxjs/toolkit';

import type { Scan } from '@/types/api';
import { loadScans, stopScan, submitScan } from './scansActions';

type ScansState = {
  items: Scan[];
  page: number;
  limit: number;
  total: number;
  loading: boolean;
  refreshing: boolean;
  creating: boolean;
  stoppingIds: number[];
  error: string | null;
};

const initialState: ScansState = {
  items: [],
  page: 1,
  limit: 25,
  total: 0,
  loading: false,
  refreshing: false,
  creating: false,
  stoppingIds: [],
  error: null,
};

export const scansSlice = createSlice({
  name: 'scans',
  initialState,
  reducers: {
    resetScans() {
      return initialState;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loadScans.pending, (state) => {
        state.error = null;
        if (state.items.length === 0) {
          state.loading = true;
        } else {
          state.refreshing = true;
        }
      })
      .addCase(loadScans.fulfilled, (state, action) => {
        state.loading = false;
        state.refreshing = false;
        state.page = action.payload.page;
        state.limit = action.payload.limit;
        state.total = action.payload.total;
        state.items = action.payload.scans;
      })
      .addCase(loadScans.rejected, (state, action) => {
        state.loading = false;
        state.refreshing = false;
        state.error =
          typeof action.payload === 'string'
            ? action.payload
            : (action.error.message ?? 'Request failed');
      })
      .addCase(submitScan.pending, (state) => {
        state.creating = true;
        state.error = null;
      })
      .addCase(submitScan.fulfilled, (state) => {
        state.creating = false;
      })
      .addCase(submitScan.rejected, (state, action) => {
        state.creating = false;
        state.error =
          action.payload ?? action.error.message ?? 'Request failed';
      })
      .addCase(stopScan.pending, (state, action) => {
        const id = action.meta.arg;
        if (!state.stoppingIds.includes(id)) {
          state.stoppingIds.push(id);
        }
      })
      .addCase(stopScan.fulfilled, (state, action) => {
        const { id, status } = action.payload;
        state.stoppingIds = state.stoppingIds.filter((value) => value !== id);
        const target = state.items.find((scan) => scan.id === id);
        if (target) {
          target.status = status;
          if (status === 'RUNNING') {
            target.cancel_requested = true;
          }
        }
      })
      .addCase(stopScan.rejected, (state, action) => {
        const id = action.meta.arg;
        state.stoppingIds = state.stoppingIds.filter((value) => value !== id);
        state.error = action.error.message ?? 'Request failed';
      });
  },
});

export const { resetScans } = scansSlice.actions;
