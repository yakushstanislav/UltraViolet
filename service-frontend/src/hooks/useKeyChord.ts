import { useEffect, useLayoutEffect, useRef } from 'react';

export type KeyChordMap = Record<string, () => void>;

export type KeyChordOptions = {
  prefix: string;
  map: KeyChordMap;
  timeoutMs?: number;
  enabled?: boolean;
};

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  if (target.isContentEditable) {
    return true;
  }

  const tag = target.tagName;

  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
}

export function useKeyChord({
  prefix,
  map,
  timeoutMs = 1500,
  enabled = true,
}: KeyChordOptions): void {
  const mapRef = useRef(map);

  useLayoutEffect(() => {
    mapRef.current = map;
  }, [map]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let armed = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const disarm = () => {
      armed = false;

      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    };

    const onKey = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }

      if (isEditableTarget(event.target)) {
        return;
      }

      const key = event.key.toLowerCase();

      if (!armed) {
        if (key === prefix.toLowerCase()) {
          armed = true;
          timer = setTimeout(disarm, timeoutMs);
        }

        return;
      }

      const handler = mapRef.current[key];

      if (handler) {
        event.preventDefault();
        handler();
      }

      disarm();
    };

    window.addEventListener('keydown', onKey);

    return () => {
      window.removeEventListener('keydown', onKey);
      disarm();
    };
  }, [prefix, timeoutMs, enabled]);
}
