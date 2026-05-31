/** Session flag: one automatic full reload was attempted after a stale dev chunk. */
export const CHUNK_RELOAD_SESSION_KEY = 'uv_chunk_reload';

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

/** True when the browser failed to load a lazy route chunk (common after Vite/HMR restarts). */
export function isChunkLoadError(error: unknown): boolean {
  const message = errorMessage(error).toLowerCase();

  return (
    message.includes('importing a module script failed') ||
    message.includes('failed to fetch dynamically imported module') ||
    message.includes('loading chunk') ||
    message.includes('chunkloaderror') ||
    message.includes('error loading dynamically imported module')
  );
}

export function clearChunkReloadFlag(): void {
  try {
    sessionStorage.removeItem(CHUNK_RELOAD_SESSION_KEY);
  } catch {
    /* sessionStorage unavailable */
  }
}

/** Reload once per tab session to pick up fresh Vite chunk URLs after a dev-server restart. */
export function reloadOnceForStaleChunk(): void {
  try {
    if (sessionStorage.getItem(CHUNK_RELOAD_SESSION_KEY) === '1') {
      return;
    }

    sessionStorage.setItem(CHUNK_RELOAD_SESSION_KEY, '1');
  } catch {
    /* fall through to reload */
  }

  window.location.reload();
}
