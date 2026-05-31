import { useMediaQuery } from './useMediaQuery';

export const BREAKPOINT_PHONE_PX = 480;
export const BREAKPOINT_PHABLET_PX = 640;
export const BREAKPOINT_TABLET_PX = 880;

const QUERY_PHONE = `(max-width: ${BREAKPOINT_PHONE_PX}px)`;
const QUERY_PHABLET = `(max-width: ${BREAKPOINT_PHABLET_PX}px)`;
const QUERY_TABLET = `(max-width: ${BREAKPOINT_TABLET_PX}px)`;
const QUERY_CAN_HOVER = '(hover: hover) and (pointer: fine)';

export type Breakpoint = 'phone' | 'phablet' | 'tablet' | 'desktop';

export function useIsPhone(): boolean {
  return useMediaQuery(QUERY_PHONE);
}

export function useIsPhablet(): boolean {
  return useMediaQuery(QUERY_PHABLET);
}

export function useIsTablet(): boolean {
  return useMediaQuery(QUERY_TABLET);
}

/** True at viewport width ≤880px (tablet and below). Use for table-vs-card list layouts. */
export function useIsMobile(): boolean {
  return useMediaQuery(QUERY_TABLET);
}

/** True at viewport width ≤880px. Use for compact shell chrome (topbar chip, overflow menu). */
export function useCompactChrome(): boolean {
  return useMediaQuery(QUERY_TABLET);
}

/** False on touch-first devices — skip hover tooltips that stick or show desktop hints. */
export function useCanHover(): boolean {
  return useMediaQuery(QUERY_CAN_HOVER);
}

export function useBreakpoint(): Breakpoint {
  const isPhone = useIsPhone();
  const isPhablet = useIsPhablet();
  const isTablet = useIsTablet();

  if (isPhone) {
    return 'phone';
  }

  if (isPhablet) {
    return 'phablet';
  }

  if (isTablet) {
    return 'tablet';
  }

  return 'desktop';
}
