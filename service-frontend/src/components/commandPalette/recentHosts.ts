import { createStringListStore } from '@helpers/createStringListStore';

const store = createStringListStore('uv_recent_hosts_v1', 6);

export function readRecentHosts(): string[] {
  return store.read();
}

export function rememberRecentHost(ip: string): void {
  store.remember(ip);
}

export function clearRecentHosts(): void {
  store.clear();
}
