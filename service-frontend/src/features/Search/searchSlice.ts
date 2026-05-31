import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

import type { SearchHit } from '@/types/api';
import { runSearch } from './searchActions';

type SearchState = {
  hits: SearchHit[];
  page: number;
  limit: number;
  total: number;
  loading: boolean;
  error: string | null;
  selectedIP: string;
};

const initialState: SearchState = {
  hits: [],
  page: 1,
  limit: 25,
  total: 0,
  loading: false,
  error: null,
  selectedIP: '',
};

export const searchSlice = createSlice({
  name: 'search',
  initialState,
  reducers: {
    selectIP(state, action: PayloadAction<string>) {
      state.selectedIP = action.payload;
    },
    resetSearch() {
      return initialState;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(runSearch.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(runSearch.fulfilled, (state, action) => {
        state.loading = false;
        state.page = action.payload.page;
        state.limit = action.payload.limit;
        state.total = action.payload.total;
        state.hits = action.payload.hits;
      })
      .addCase(runSearch.rejected, (state, action) => {
        if (action.meta.aborted) {
          return;
        }

        state.loading = false;
        state.error = action.error.message ?? 'Request failed';
      });
  },
});

export const { selectIP, resetSearch } = searchSlice.actions;
