import { useEffect, useRef } from 'react';

import { realtime } from '@services/realtimeClient';
import type { RealtimeEvent } from '@/types/realtime';

export function useRealtimeEvents(
  types: string[],
  handler: (event: RealtimeEvent) => void,
): void {
  const handlerRef = useRef(handler);

  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  const typesKey = types.join('\0');

  useEffect(() => {
    return realtime.subscribe(types, (event) => {
      handlerRef.current(event);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- stable subscription key
  }, [typesKey]);
}

export function useRealtimeScan(
  scanId: number | null,
  handler: (event: RealtimeEvent) => void,
): void {
  const handlerRef = useRef(handler);

  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  useEffect(() => {
    if (scanId === null) {
      return;
    }

    return realtime.subscribeScan(scanId, (event) => {
      handlerRef.current(event);
    });
  }, [scanId]);
}
