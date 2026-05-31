import { useEffect, useRef, useState } from 'react';

/**
 * Tracks status changes across a list and returns IDs that just transitioned.
 * Used to drive short-lived row highlight animations.
 */
export function useStatusFlash<T extends { id: number; status: string }>(
  items: T[],
  durationMs = 1400
): number[] {
  const [flashedIds, setFlashedIds] = useState<number[]>([]);
  const previousStatus = useRef<Map<number, string>>(new Map());

  useEffect(() => {
    const changed: number[] = [];
    const next = new Map<number, string>();

    items.forEach((item) => {
      next.set(item.id, item.status);
      const prev = previousStatus.current.get(item.id);
      if (prev && prev !== item.status) {
        changed.push(item.id);
      }
    });

    previousStatus.current = next;

    if (changed.length === 0) {
      return;
    }

    setFlashedIds(changed);
    const timer = window.setTimeout(() => setFlashedIds([]), durationMs);

    return () => window.clearTimeout(timer);
  }, [items, durationMs]);

  return flashedIds;
}
