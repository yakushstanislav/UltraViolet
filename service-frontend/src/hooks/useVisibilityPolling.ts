import { useEffect } from 'react';

export type PollingOptions = {
  enabled: boolean;
  intervalMs: number;
};

/**
 * Runs `callback` on a timer while the tab is visible. Triggers an immediate
 * call on visibilitychange when returning from a hidden tab so the UI is
 * always fresh on focus.
 */
export function useVisibilityPolling(
  callback: () => void,
  { enabled, intervalMs }: PollingOptions
): void {
  useEffect(() => {
    if (!enabled) {
      return;
    }

    let timer: number | null = null;

    const start = () => {
      if (timer !== null) {
        return;
      }

      timer = window.setInterval(() => {
        if (document.visibilityState === 'visible') {
          callback();
        }
      }, intervalMs);
    };

    const stop = () => {
      if (timer !== null) {
        window.clearInterval(timer);
        timer = null;
      }
    };

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        callback();
        start();
      } else {
        stop();
      }
    };

    if (document.visibilityState === 'visible') {
      start();
    }

    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [callback, enabled, intervalMs]);
}
