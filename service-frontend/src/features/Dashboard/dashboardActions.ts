import { createAsyncThunk } from '@reduxjs/toolkit';

import { getDashboardStats } from '@services/DashboardAPI';

export const loadDashboard = createAsyncThunk('dashboard/load', () =>
  getDashboardStats()
);
