import { createStringListStore } from './createStringListStore';

const store = createStringListStore('uv_recent_scan_targets_v1', 8);

export function readRecentScanTargets(): string[] {
  return store.read();
}

export function rememberScanTarget(target: string): void {
  store.remember(target);
}
