import {
  Activity,
  Bell,
  BellRing,
  Bookmark,
  BookmarkCheck,
  CalendarClock,
  Database,
  LayoutGrid,
  Network,
  Search,
  Shield,
  Sliders,
  Users,
  type LucideIcon,
} from 'lucide-react';

import type { AppRole } from '@/types/users';

/** URL prefix for operator-management pages (users, audit). Not `/admin` on purpose. */
export const MANAGE_BASE_PATH = '/manage';
export const MANAGE_USERS_PATH = `${MANAGE_BASE_PATH}/users`;
export const MANAGE_AUDIT_PATH = `${MANAGE_BASE_PATH}/audit`;

export type AppRoute = {
  path: string;
  /** Matcher for breadcrumb derivation. Prefix match if endsWith '*'. */
  match: string | RegExp;
  icon: LucideIcon;
  /** Segments for the uv://x · y breadcrumb. Last segment may be a placeholder. */
  segments: (params: { pathname: string }) => string[];
};

export type NavRoute = {
  to: string;
  /** i18n key under default namespace (e.g. nav.overview). */
  labelKey: string;
  icon: LucideIcon;
  /** Minimum role required to see this nav item. Omit for all authenticated users. */
  role?: AppRole;
};

export type NavGroup = {
  key: string;
  /** i18n key for the section label. Omit → no label rendered. */
  labelKey?: string;
  routes: NavRoute[];
};

export const NAV_GROUPS: NavGroup[] = [
  {
    key: 'core',
    routes: [
      { to: '/dashboard', labelKey: 'nav.overview', icon: Database },
    ],
  },
  {
    key: 'scan',
    labelKey: 'nav.groupScan',
    routes: [
      { to: '/search', labelKey: 'nav.query', icon: Search },
      { to: '/scans', labelKey: 'nav.jobs', icon: Activity },
      { to: '/saved-searches', labelKey: 'nav.saved', icon: Bookmark },
      { to: '/scan-schedules', labelKey: 'nav.schedules', icon: CalendarClock },
    ],
  },
  {
    key: 'monitor',
    labelKey: 'nav.groupMonitor',
    routes: [
      { to: '/alerts', labelKey: 'nav.alerts', icon: Bell },
    ],
  },
  {
    key: 'admin',
    labelKey: 'nav.groupAdmin',
    routes: [
      { to: '/risk/policies', labelKey: 'nav.policies', icon: Sliders, role: 'admin' },
      { to: MANAGE_USERS_PATH, labelKey: 'nav.users', icon: Users, role: 'admin' },
      { to: MANAGE_AUDIT_PATH, labelKey: 'nav.audit', icon: Shield, role: 'admin' },
    ],
  },
];

export const NAV_ROUTES: NavRoute[] = NAV_GROUPS.flatMap((g) => g.routes);

export const BREADCRUMB_ROUTES: AppRoute[] = [
  {
    path: '/search',
    match: '/search',
    icon: Search,
    segments: () => ['search', 'console'],
  },
  {
    path: '/scans/:id',
    match: /^\/scans\/[^/]+$/,
    icon: Activity,
    segments: ({ pathname }) => {
      const id = pathname.split('/').pop() ?? '';

      return ['scans', 'queue', id];
    },
  },
  {
    path: '/scans',
    match: '/scans',
    icon: Activity,
    segments: () => ['scans', 'queue'],
  },
  {
    path: '/hosts/:ip',
    match: /^\/hosts\/[^/]+$/,
    icon: Database,
    segments: ({ pathname }) => {
      const ip = pathname.split('/').pop() ?? '';

      return ['hosts', ip];
    },
  },
  {
    path: '/saved-searches',
    match: '/saved-searches',
    icon: BookmarkCheck,
    segments: () => ['saved', 'searches'],
  },
  {
    path: '/alerts',
    match: '/alerts',
    icon: BellRing,
    segments: () => ['alerts', 'rules'],
  },
  {
    path: '/scan-schedules',
    match: '/scan-schedules',
    icon: CalendarClock,
    segments: () => ['scans', 'schedules'],
  },
  {
    path: '/risk/policies',
    match: '/risk/policies',
    icon: Sliders,
    segments: () => ['risk', 'policies'],
  },
  {
    path: '/attack-paths/:ip',
    match: /^\/attack-paths\/[^/]+$/,
    icon: Network,
    segments: ({ pathname }) => {
      const ip = pathname.split('/').pop() ?? '';

      return ['attackPaths', ip];
    },
  },
  {
    path: MANAGE_USERS_PATH,
    match: MANAGE_USERS_PATH,
    icon: Users,
    segments: () => ['manage', 'users'],
  },
  {
    path: MANAGE_AUDIT_PATH,
    match: MANAGE_AUDIT_PATH,
    icon: Shield,
    segments: () => ['manage', 'audit'],
  },
];

export type Breadcrumb = {
  icon: LucideIcon;
  segments: string[];
};

export type BreadcrumbNav = Breadcrumb & {
  /** Parallel to `segments`; `undefined` = current leaf, not a link. */
  hrefs: (string | undefined)[];
};

export const BREADCRUMB_ROOT_HREF = '/dashboard';

const BREADCRUMB_TRANSLATABLE = new Set([
  'search',
  'console',
  'scans',
  'queue',
  'hosts',
  'saved',
  'searches',
  'alerts',
  'rules',
  'overview',
  'schedules',
  'manage',
  'users',
  'audit',
  'risk',
  'events',
  'policies',
  'recommendations',
  'attackPaths',
]);

export function translateBreadcrumbSegment(
  segment: string,
  t: (key: string) => string
): string {
  if (BREADCRUMB_TRANSLATABLE.has(segment)) {
    return t(`breadcrumb.${segment}`);
  }

  return segment;
}

export function getBreadcrumb(pathname: string): Breadcrumb {
  for (const route of BREADCRUMB_ROUTES) {
    if (typeof route.match === 'string') {
      if (route.match === pathname) {
        return { icon: route.icon, segments: route.segments({ pathname }) };
      }
    } else if (route.match.test(pathname)) {
      return { icon: route.icon, segments: route.segments({ pathname }) };
    }
  }

  return { icon: LayoutGrid, segments: ['overview'] };
}

function breadcrumbHrefForSegment(
  pathname: string,
  segmentIndex: number,
  segmentCount: number
): string | undefined {
  if (segmentIndex >= segmentCount - 1) {
    return undefined;
  }

  if (pathname === '/dashboard' || pathname === '/') {
    return segmentIndex === 0 ? BREADCRUMB_ROOT_HREF : undefined;
  }

  if (pathname === '/search') {
    return segmentIndex === 0 ? '/search' : undefined;
  }

  if (pathname === '/scans') {
    return segmentIndex === 0 ? '/scans' : undefined;
  }

  if (pathname.startsWith('/scans/')) {
    return segmentIndex <= 1 ? '/scans' : undefined;
  }

  if (pathname.startsWith('/hosts/')) {
    return segmentIndex === 0 ? '/search' : undefined;
  }

  if (pathname.startsWith('/saved-searches')) {
    return segmentIndex === 0 ? '/saved-searches' : undefined;
  }

  if (pathname.startsWith('/alerts')) {
    return segmentIndex === 0 ? '/alerts' : undefined;
  }

  if (pathname.startsWith('/scan-schedules')) {
    return segmentIndex === 0 ? '/scan-schedules' : undefined;
  }

  if (pathname.startsWith(MANAGE_USERS_PATH)) {
    return segmentIndex === 0 ? MANAGE_USERS_PATH : undefined;
  }

  if (pathname.startsWith(MANAGE_AUDIT_PATH)) {
    return segmentIndex === 0 ? MANAGE_AUDIT_PATH : undefined;
  }

  if (pathname.startsWith('/risk/policies')) {
    return segmentIndex === 0 ? '/risk/policies' : undefined;
  }

  if (pathname.startsWith('/attack-paths/')) {
    return segmentIndex === 0 ? '/search' : undefined;
  }

  return segmentIndex === 0 ? BREADCRUMB_ROOT_HREF : undefined;
}

export function getBreadcrumbNav(pathname: string): BreadcrumbNav {
  const base = getBreadcrumb(pathname);
  const hrefs = base.segments.map((_, index) =>
    breadcrumbHrefForSegment(pathname, index, base.segments.length)
  );

  return { ...base, hrefs };
}
