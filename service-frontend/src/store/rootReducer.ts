import { combineReducers } from '@reduxjs/toolkit';

import { authSlice } from '@features/Auth/authSlice';
import { dashboardSlice } from '@features/Dashboard/dashboardSlice';
import { hostSlice } from '@features/Host/hostSlice';
import { scansSlice } from '@features/Scans/scansSlice';
import { searchSlice } from '@features/Search/searchSlice';
import { uiSlice } from './uiSlice';

export const rootReducer = combineReducers({
  auth: authSlice.reducer,
  dashboard: dashboardSlice.reducer,
  host: hostSlice.reducer,
  scans: scansSlice.reducer,
  search: searchSlice.reducer,
  ui: uiSlice.reducer,
});
