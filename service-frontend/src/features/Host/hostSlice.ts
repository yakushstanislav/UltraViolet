import { createSlice } from '@reduxjs/toolkit';

import type { Host } from '@/types/api';
import { loadHost } from './hostActions';

type HostState = {
  data: Host | null;
  loading: boolean;
  error: string | null;
};

const initialState: HostState = {
  data: null,
  loading: false,
  error: null,
};

export const hostSlice = createSlice({
  name: 'host',
  initialState,
  reducers: {
    resetHost() {
      return initialState;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loadHost.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loadHost.fulfilled, (state, action) => {
        state.loading = false;
        state.data = action.payload;
      })
      .addCase(loadHost.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message ?? 'Request failed';
      });
  },
});

export const { resetHost } = hostSlice.actions;
