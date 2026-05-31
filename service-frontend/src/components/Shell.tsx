import {
  LogOut,
  Menu,
  Moon,
  Search,
  ShieldCheck,
  Sun,
  X,
} from 'lucide-react';
import { lazy, Suspense, useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';

import { AppErrorBoundary } from './AppErrorBoundary';
import { BottomNav } from './BottomNav';
import { BrandMark } from './BrandMark';
import { BreadcrumbSheet } from './BreadcrumbSheet';
const CommandPaletteLazy = lazy(() =>
  import('./CommandPalette').then((module) => ({
    default: module.CommandPalette,
  }))
);
import { RealtimeConnectionPill } from './RealtimeConnectionPill';
import { ShortcutsOverlay } from './ShortcutsOverlay';
import { Tooltip, TooltipProvider } from './Tooltip';
import { TopbarOverflowMenu } from './TopbarOverflowMenu';
import {
  BREADCRUMB_ROOT_HREF,
  NAV_GROUPS,
  getBreadcrumbNav,
  translateBreadcrumbSegment,
} from '@app/routes';
import type { NavRoute } from '@app/routes';
import { logoutUser } from '@features/Auth/authSlice';
import { useDemoMode } from '@/hooks/useDemoMode';
import { getKbdHint, readKbdHintAriaLabel } from '@helpers/platform';
import { useGlobalShortcut } from '@/hooks/useGlobalShortcut';
import { useIsPhablet, useIsTablet } from '@/hooks/useBreakpoint';
import { useKeyChord } from '@/hooks/useKeyChord';
import { useSwipeGesture } from '@/hooks/useSwipeGesture';
import { useAppDispatch, useAppSelector } from '@store/store';
import type { AppRole } from '@/types/users';
import { useTheme } from '@/theme/ThemeProvider';

export function Shell() {
  const { t } = useTranslation();
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const role = useAppSelector((state) => state.auth.role) as AppRole | null;
  const demoMode = useDemoMode();
  const { theme, toggleTheme } = useTheme();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [breadcrumbSheetOpen, setBreadcrumbSheetOpen] = useState(false);
  const location = useLocation();
  const isPhablet = useIsPhablet();
  const isCompactTopbar = useIsTablet();
  const isMobileTopbar = isCompactTopbar;

  const closeMobileNav = useCallback(() => setMobileNavOpen(false), []);
  const openMobileNav = useCallback(() => setMobileNavOpen(true), []);
  const currentPath = location.pathname;

  const breadcrumb = useMemo(
    () => getBreadcrumbNav(currentPath),
    [currentPath]
  );

  const roleClass =
    role === 'admin'
      ? 'role-admin'
      : role === 'operator'
        ? 'role-operator'
        : 'role-viewer';
  const RoleIcon = ShieldCheck;
  const PageIcon = breadcrumb.icon;
  const breadcrumbLeafSegment =
    breadcrumb.segments[breadcrumb.segments.length - 1] ?? '';
  const breadcrumbLeafLabel = translateBreadcrumbSegment(
    breadcrumbLeafSegment,
    t
  );

  const togglePalette = useCallback((event: KeyboardEvent) => {
    event.preventDefault();
    setPaletteOpen((current) => !current);
  }, []);

  const openShortcuts = useCallback((event: KeyboardEvent) => {
    event.preventDefault();
    setShortcutsOpen(true);
  }, []);

  useGlobalShortcut('k', togglePalette);
  useGlobalShortcut('?', openShortcuts, {});

  useKeyChord({
    prefix: 'g',
    map: {
      h: () => navigate('/dashboard'),
      d: () => navigate('/dashboard'),
      s: () => navigate('/scans'),
      q: () => navigate('/search'),
      a: () => navigate('/alerts'),
    },
  });

  const handleLogout = useCallback(() => {
    void dispatch(logoutUser());
  }, [dispatch]);

  const edgeSwipe = useSwipeGesture({
    onSwipeRight: openMobileNav,
    edgeOnly: 24,
    disabled: !isCompactTopbar || mobileNavOpen,
  });

  const sidebarSwipe = useSwipeGesture({
    onSwipeLeft: closeMobileNav,
    disabled: !isCompactTopbar || !mobileNavOpen,
  });

  const kbdHint = getKbdHint('K');
  const roleLabel = role ?? t('shell.roleViewer');
  return (
    <TooltipProvider delayDuration={300}>
      <a className="skip-link" href="#uv-main">
        {t('shell.skipToMain')}
      </a>
      {demoMode && (
        <div className="demo-banner" role="status">
          {t('demoBanner.message')}
        </div>
      )}
      <div
        className={`shell ${mobileNavOpen ? 'sidebar-open' : ''}`}
        {...edgeSwipe}
      >
      {mobileNavOpen && (
        <button
          aria-label={t('shell.closeNavigation')}
          className="mobile-nav-backdrop"
          onClick={closeMobileNav}
          type="button"
        />
      )}
      <aside className="sidebar" {...sidebarSwipe}>
        <div className="brand">
          <BrandMark className="brand-mark" size={24} />
          <div>
            <span>{t('app.title')}</span>
            <span className="brand-subtitle">{t('shell.brandSubtitle')}</span>
          </div>
        </div>
        <nav className="nav">
          {NAV_GROUPS.map((group) => {
            const groupRoutes = group.routes.filter(
              (r: NavRoute) => !r.role || role === 'admin',
            );

            if (groupRoutes.length === 0) {
              return null;
            }

            const isActiveGroup = groupRoutes.some(
              (r: NavRoute) =>
                currentPath === r.to || currentPath.startsWith(`${r.to}/`),
            );

            return (
              <div
                className={`nav-group${isActiveGroup ? ' active-group' : ''}`}
                key={group.key}
              >
                {group.labelKey != null && (
                  <span aria-hidden className="nav-group-label">
                    {t(group.labelKey)}
                  </span>
                )}
                {groupRoutes.map(({ to, labelKey, icon: Icon }) => (
                  <NavLink key={to} onClick={closeMobileNav} to={to}>
                    <Icon size={18} />
                    {t(labelKey)}
                  </NavLink>
                ))}
              </div>
            );
          })}
        </nav>
      </aside>
      <main className="main" id="uv-main" tabIndex={-1}>
        <header className="topbar">
          <Tooltip
            label={
              mobileNavOpen
                ? t('shell.closeNavigation')
                : t('shell.openNavigation')
            }
          >
            <button
              aria-label={
                mobileNavOpen
                  ? t('shell.closeNavigation')
                  : t('shell.openNavigation')
              }
              className="mobile-nav-toggle secondary"
              onClick={() => setMobileNavOpen((current) => !current)}
              type="button"
            >
              {mobileNavOpen ? <X size={16} /> : <Menu size={16} />}
            </button>
          </Tooltip>
          <div className="topbar-title">
            <span className="topbar-title-icon">
              <PageIcon size={16} />
            </span>
            {isMobileTopbar ? (
              <button
                aria-label={t('shell.viewFullPath')}
                className="uv-breadcrumb-chip"
                onClick={() => setBreadcrumbSheetOpen(true)}
                type="button"
              >
                <span className="uv-breadcrumb-chip__label">
                  {breadcrumbLeafLabel}
                </span>
              </button>
            ) : (
              <span className="topbar-breadcrumb">
                <Link
                  className="topbar-breadcrumb-prefix topbar-breadcrumb-link"
                  title={t('breadcrumb.goRoot')}
                  to={BREADCRUMB_ROOT_HREF}
                >
                  uv://
                </Link>
                {breadcrumb.segments.map((segment, index) => {
                  const href = breadcrumb.hrefs[index];
                  const label = translateBreadcrumbSegment(segment, t);
                  const isLeaf = index === breadcrumb.segments.length - 1;

                  return (
                    <span
                      className="topbar-breadcrumb-segment"
                      key={`${segment}-${index}`}
                    >
                      {index > 0 && (
                        <span className="topbar-breadcrumb-sep">·</span>
                      )}
                      {href !== undefined && !isLeaf ? (
                        <Link
                          className={
                            index === 0
                              ? 'topbar-breadcrumb-root topbar-breadcrumb-link'
                              : 'topbar-breadcrumb-leaf topbar-breadcrumb-link'
                          }
                          to={href}
                        >
                          {label}
                        </Link>
                      ) : (
                        <span
                          className={
                            index === 0
                              ? 'topbar-breadcrumb-root'
                              : 'topbar-breadcrumb-leaf'
                          }
                        >
                          {label}
                        </span>
                      )}
                    </span>
                  );
                })}
              </span>
            )}
          </div>
          <Tooltip label={`${t('shell.openCommandPalette')} (${kbdHint})`}>
            <button
              aria-label={t('shell.openCommandPalette')}
              className="topbar-command-trigger"
              onClick={() => setPaletteOpen(true)}
              type="button"
            >
              <Search size={14} />
              <span className="topbar-command-placeholder">
                {t('shell.searchHostsPlaceholder')}
              </span>
              <kbd
                aria-label={readKbdHintAriaLabel(kbdHint)}
                className="topbar-command-kbd"
              >
                {kbdHint}
              </kbd>
            </button>
          </Tooltip>
          <div className="topbar-spacer" />
          <RealtimeConnectionPill />
          {isMobileTopbar ? (
            <TopbarOverflowMenu
              onLogout={handleLogout}
              role={role}
              roleClass={roleClass}
              roleLabel={roleLabel}
            />
          ) : (
            <>
              <div
                aria-label={t('shell.signedInAs', { role: roleLabel })}
                className={`session-pill ${roleClass}`}
              >
                <span aria-hidden className="session-pill-icon">
                  <RoleIcon size={14} />
                </span>
                <span className="session-pill-label">{roleLabel}</span>
              </div>
              <div className="topbar-actions">
                <Tooltip label={t('shell.toggleTheme')}>
                  <button
                    aria-label={t('shell.toggleTheme')}
                    className="topbar-icon-btn topbar-theme-btn"
                    onClick={toggleTheme}
                    type="button"
                  >
                    {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
                  </button>
                </Tooltip>
                <div aria-hidden className="topbar-actions-divider" />
                <Tooltip label={t('shell.disconnect')}>
                  <button
                    aria-label={t('shell.disconnect')}
                    className="topbar-icon-btn topbar-logout-btn"
                    onClick={handleLogout}
                    type="button"
                  >
                    <LogOut size={15} />
                  </button>
                </Tooltip>
              </div>
            </>
          )}
        </header>
        <AppErrorBoundary resetKey={currentPath}>
          <Outlet />
        </AppErrorBoundary>
        {paletteOpen ? (
          <Suspense fallback={null}>
            <CommandPaletteLazy
              onOpenChange={setPaletteOpen}
              open={paletteOpen}
            />
          </Suspense>
        ) : null}
        <ShortcutsOverlay
          onOpenChange={setShortcutsOpen}
          open={shortcutsOpen}
        />
        <BreadcrumbSheet
          breadcrumb={breadcrumb}
          onOpenChange={setBreadcrumbSheetOpen}
          open={breadcrumbSheetOpen}
        />
        {isPhablet && <BottomNav role={role} />}
      </main>
      </div>
    </TooltipProvider>
  );
}
