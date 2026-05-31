import { createStringListStore } from '@helpers/createStringListStore';

const store = createStringListStore('uv_search_history_v1', 8);

export function readSearchHistory(): string[] {
  return store.read();
}

export function rememberSearchQuery(raw: string): void {
  store.remember(raw);
}

export function clearSearchHistory(): void {
  store.clear();
}
