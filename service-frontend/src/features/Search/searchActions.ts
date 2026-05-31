import { createAsyncThunk } from '@reduxjs/toolkit';

import { search, type SearchParams } from '@services/SearchAPI';

export const runSearch = createAsyncThunk(
  'search/run',
  (params: SearchParams, thunkAPI) => search(params, thunkAPI.signal)
);
