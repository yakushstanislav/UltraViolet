import { reloadOnceForStaleChunk } from './chunkLoadError';

/**
 * Vite emits vite:preloadError when a preloaded module hash no longer exists
 * (e.g. after `npm run dev` restart). Recover with a single full reload.
 */
export function registerViteChunkRecovery(): void {
  if (!import.meta.env.DEV) {
    return;
  }

  window.addEventListener('vite:preloadError', (event) => {
    event.preventDefault();
    reloadOnceForStaleChunk();
  });
}
