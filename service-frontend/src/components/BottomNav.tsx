import { Activity, Bell, Database, MoreHorizontal, Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { NavLink } from 'react-router-dom';

import { NAV_ROUTES } from '@app/routes';
import { NavMoreSheet } from './NavMoreSheet';
import type { AppRole } from '@/types/users';

type BottomNavItem = {
  to: string;
  labelKey: string;
  icon: typeof Database;
};

const BOTTOM_NAV_ITEMS: BottomNavItem[] = [
  { to: '/dashboard', labelKey: 'nav.overview', icon: Database },
  { to: '/search', labelKey: 'nav.query', icon: Search },
  { to: '/scans', labelKey: 'nav.jobs', icon: Activity },
  { to: '/alerts', labelKey: 'nav.alerts', icon: Bell },
];

const BOTTOM_NAV_PATHS = new Set(BOTTOM_NAV_ITEMS.map((item) => item.to));

type BottomNavProps = {
  role: AppRole | null;
};

function hasMoreRoutes(role: AppRole | null): boolean {
  return NAV_ROUTES.some((route) => {
    if (BOTTOM_NAV_PATHS.has(route.to)) {
      return false;
    }

    if (!route.role) {
      return true;
    }

    return role === 'admin';
  });
}

export function BottomNav({ role }: BottomNavProps) {
  const { t } = useTranslation();
  const [moreOpen, setMoreOpen] = useState(false);
  const showMore = useMemo(() => hasMoreRoutes(role), [role]);

  return (
    <>
      <nav aria-label={t('shell.bottomNavLabel')} className="uv-bottomnav">
        {BOTTOM_NAV_ITEMS.map(({ to, labelKey, icon: Icon }) => (
          <NavLink className="uv-bottomnav__item" key={to} to={to}>
            <Icon aria-hidden className="uv-bottomnav__icon" size={20} />
            <span className="uv-bottomnav__label">{t(labelKey)}</span>
          </NavLink>
        ))}
        {showMore && (
          <button
            aria-expanded={moreOpen}
            aria-haspopup="dialog"
            aria-label={t('shell.navMoreTitle')}
            className="uv-bottomnav__item uv-bottomnav__item--more"
            onClick={() => setMoreOpen(true)}
            type="button"
          >
            <MoreHorizontal aria-hidden className="uv-bottomnav__icon" size={20} />
            <span className="uv-bottomnav__label">{t('shell.navMoreShort')}</span>
          </button>
        )}
      </nav>
      {showMore && (
        <NavMoreSheet onOpenChange={setMoreOpen} open={moreOpen} role={role} />
      )}
    </>
  );
}
