import type { SearchQuery } from './common';

export type SavedSearch = {
  id: number;
  name: string;
  query: SearchQuery;
  created_at: string;
  updated_at: string;
  last_run_at?: string;
};

export type SavedSearchListResponse = {
  page: number;
  limit: number;
  total: number;
  items: SavedSearch[];
};

export type RunSavedSearchResponse = {
  id: number;
  name: string;
  query: SearchQuery;
};
