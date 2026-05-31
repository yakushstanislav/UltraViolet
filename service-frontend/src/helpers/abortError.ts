// Pinned to axios CanceledError + DOM AbortError so the same predicate
// works whether the request was cancelled via AbortController (preferred)
// or by axios' internal cancellation path.
export function isAbortError(err: unknown): boolean {
  if (err == null || typeof err !== 'object') {
    return false;
  }

  const name = (err as { name?: unknown }).name;

  return name === 'AbortError' || name === 'CanceledError';
}
