import { createSlice } from '@reduxjs/toolkit';

import type { DashboardStats } from '@/types/api';

import { loadDashboard } from './dashboardActions';

type DashboardState = {
  data: DashboardStats | null;
  loading: boolean;
  error: string | null;
};

const initialState: DashboardState = {
  data: null,
  loading: false,
  error: null,
};

export const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    resetDashboard() {
      return initialState;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loadDashboard.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loadDashboard.fulfilled, (state, action) => {
        state.loading = false;
        state.data = action.payload;
      })
      .addCase(loadDashboard.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message ?? 'Request failed';
      });
  },
});

export const { resetDashboard } = dashboardSlice.actions;
