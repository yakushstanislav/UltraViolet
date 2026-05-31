import { useCallback, useEffect, useRef, useState } from 'react';

type UseAsyncWidgetOptions<T> = {
  fetcher: () => Promise<T>;
  fallbackError: string;
};

export function useAsyncWidget<T>({
  fetcher,
  fallbackError,
}: UseAsyncWidgetOptions<T>) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const nonceRef = useRef(0);

  const reload = useCallback(async () => {
    const myNonce = nonceRef.current + 1;
    nonceRef.current = myNonce;

    setLoading(true);
    setError(null);

    try {
      const result = await fetcher();
      if (myNonce !== nonceRef.current) {
        return;
      }

      setData(result);
      setLastUpdated(new Date());
    } catch (err) {
      if (myNonce !== nonceRef.current) {
        return;
      }

      setData(null);
      setError(err instanceof Error ? err.message : fallbackError);
    } finally {
      if (myNonce === nonceRef.current) {
        setLoading(false);
      }
    }
  }, [fetcher, fallbackError]);

  useEffect(() => {
    void reload();
  }, [reload]);

  return { data, loading, error, lastUpdated, reload };
}
