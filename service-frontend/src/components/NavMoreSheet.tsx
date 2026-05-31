import * as Dialog from '@radix-ui/react-dialog';
import { useTranslation } from 'react-i18next';
import { NavLink } from 'react-router-dom';

import { NAV_ROUTES, type NavRoute } from '@app/routes';
import type { AppRole } from '@/types/users';

const BOTTOM_NAV_PATHS = new Set([
  '/dashboard',
  '/search',
  '/scans',
  '/alerts',
]);

type NavMoreSheetProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role: AppRole | null;
};

function isRouteVisible(route: NavRoute, role: AppRole | null): boolean {
  if (!route.role) {
    return true;
  }

  return role === 'admin';
}

export function NavMoreSheet({ open, onOpenChange, role }: NavMoreSheetProps) {
  const { t } = useTranslation();

  const moreRoutes = NAV_ROUTES.filter(
    (route) => !BOTTOM_NAV_PATHS.has(route.to) && isRouteVisible(route, role)
  );

  if (moreRoutes.length === 0) {
    return null;
  }

  return (
    <Dialog.Root onOpenChange={onOpenChange} open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay nav-more-sheet-overlay" />
        <Dialog.Content
          aria-describedby={undefined}
          className="dialog uv-dialog--sheet nav-more-sheet"
        >
          <div className="uv-dialog__handle" />
          <Dialog.Title className="nav-more-sheet-title">
            {t('shell.navMoreTitle')}
          </Dialog.Title>
          <nav aria-label={t('shell.navMoreLabel')} className="nav-more-sheet-list">
            {moreRoutes.map(({ to, labelKey, icon: Icon }) => (
              <NavLink
                className="nav-more-sheet-link"
                key={to}
                onClick={() => onOpenChange(false)}
                to={to}
              >
                <Icon aria-hidden size={18} />
                <span>{t(labelKey)}</span>
              </NavLink>
            ))}
          </nav>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
