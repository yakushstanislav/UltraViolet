import { createStringListStore } from './createStringListStore';

const store = createStringListStore('uv_recent_search_queries_v1', 20);

export function readRecentSearchQueries(): string[] {
  return store.read();
}

export function rememberSearchQuery(query: string): void {
  store.remember(query);
}
