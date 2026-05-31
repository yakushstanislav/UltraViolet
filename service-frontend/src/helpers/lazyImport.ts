import { isChunkLoadError, reloadOnceForStaleChunk } from './chunkLoadError';

const RETRY_DELAY_MS = 200;
const MAX_ATTEMPTS = 3;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

/**
 * Wraps dynamic import() for React.lazy routes. Retries transient failures and,
 * in dev, performs a one-time full page reload when Vite chunk URLs are stale.
 */
export async function lazyImport<T>(loader: () => Promise<T>): Promise<T> {
  let lastError: unknown;

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    try {
      return await loader();
    } catch (error) {
      lastError = error;

      if (!isChunkLoadError(error)) {
        throw error;
      }

      if (attempt < MAX_ATTEMPTS - 1) {
        await delay(RETRY_DELAY_MS * (attempt + 1));
        continue;
      }
    }
  }

  if (import.meta.env.DEV && isChunkLoadError(lastError)) {
    reloadOnceForStaleChunk();

    return new Promise<T>(() => {
      /* page reload in progress */
    });
  }

  throw lastError;
}
