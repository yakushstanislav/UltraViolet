import { useCallback, useRef } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';

export type SwipeHandlers = {
  onPointerDown: (event: ReactPointerEvent<HTMLElement>) => void;
  onPointerMove: (event: ReactPointerEvent<HTMLElement>) => void;
  onPointerUp: (event: ReactPointerEvent<HTMLElement>) => void;
  onPointerCancel: (event: ReactPointerEvent<HTMLElement>) => void;
};

export type UseSwipeGestureOptions = {
  onSwipeLeft?: () => void;
  onSwipeRight?: () => void;
  onSwipeUp?: () => void;
  onSwipeDown?: () => void;
  /** Minimum displacement in pixels to count as a swipe (default 50). */
  threshold?: number;
  /**
   * When set, horizontal swipes only fire if the pointer started within this
   * many pixels of the left edge (for onSwipeRight) or right edge (for onSwipeLeft).
   * Useful for edge-drawer gestures that should not intercept page scrolling.
   */
  edgeOnly?: number;
  /** Disable gesture handling entirely (e.g. on desktop). */
  disabled?: boolean;
};

type StartPoint = {
  pointerId: number;
  startX: number;
  startY: number;
};

export function useSwipeGesture(options: UseSwipeGestureOptions): SwipeHandlers {
  const {
    onSwipeLeft,
    onSwipeRight,
    onSwipeUp,
    onSwipeDown,
    threshold = 50,
    edgeOnly,
    disabled = false,
  } = options;

  const startRef = useRef<StartPoint | null>(null);

  const reset = useCallback(() => {
    startRef.current = null;
  }, []);

  const onPointerDown = useCallback(
    (event: ReactPointerEvent<HTMLElement>) => {
      if (disabled) {
        return;
      }

      const viewportW = window.innerWidth;

      if (edgeOnly !== undefined && onSwipeRight) {
        if (event.clientX > edgeOnly) {
          if (!onSwipeLeft || event.clientX < viewportW - edgeOnly) {
            return;
          }
        }
      }

      startRef.current = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
      };
    },
    [disabled, edgeOnly, onSwipeLeft, onSwipeRight]
  );

  const onPointerMove = useCallback(() => {
    /* no-op — final direction is computed on pointer up */
  }, []);

  const onPointerUp = useCallback(
    (event: ReactPointerEvent<HTMLElement>) => {
      const start = startRef.current;

      if (!start || start.pointerId !== event.pointerId) {
        return;
      }

      const dx = event.clientX - start.startX;
      const dy = event.clientY - start.startY;
      const absDx = Math.abs(dx);
      const absDy = Math.abs(dy);

      reset();

      if (absDx < threshold && absDy < threshold) {
        return;
      }

      if (absDx >= absDy) {
        if (dx > 0 && onSwipeRight) {
          onSwipeRight();
        } else if (dx < 0 && onSwipeLeft) {
          onSwipeLeft();
        }

        return;
      }

      if (dy > 0 && onSwipeDown) {
        onSwipeDown();
      } else if (dy < 0 && onSwipeUp) {
        onSwipeUp();
      }
    },
    [onSwipeDown, onSwipeLeft, onSwipeRight, onSwipeUp, reset, threshold]
  );

  return {
    onPointerDown,
    onPointerMove,
    onPointerUp,
    onPointerCancel: reset,
  };
}
