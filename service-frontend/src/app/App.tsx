import { Suspense, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, Route, Routes } from 'react-router-dom';

import {
  AlertsPage,
  AttackPathPage,
  AuditPage,
  DashboardPage,
  HostPage,
  RiskPolicyPage,
  SavedSearchesPage,
  ScanDetailPage,
  ScanSchedulesPage,
  ScansPage,
  SearchPage,
  PivotPage,
  UsersPage,
} from '@app/lazyPages';
import { MANAGE_AUDIT_PATH, MANAGE_USERS_PATH } from '@app/routes';
import { AppErrorBoundary } from '@components/AppErrorBoundary';
import { Shell } from '@components/Shell';
import { AccessDeniedPage } from '@features/Auth/AccessDeniedPage';
import { LoginPage } from '@features/Auth/LoginPage';
import { RequireAuth } from '@features/Auth/RequireAuth';
import { RequireRole } from '@features/Auth/RequireRole';
import { useAppSelector } from '@store/store';

function RouteFallback() {
  const { t } = useTranslation();
  return (
    <section className="page">
      <div className="notice">{t('common.loading')}</div>
    </section>
  );
}

function lazyRoute(element: ReactNode): ReactNode {
  return (
    <AppErrorBoundary>
      <Suspense fallback={<RouteFallback />}>{element}</Suspense>
    </AppErrorBoundary>
  );
}

export function App() {
  const isGlobalLoading = useAppSelector(
    (state) => state.auth.loading || state.ui.blockingTaskCount > 0
  );

  return (
    <>
      <div
        aria-hidden={!isGlobalLoading}
        className={`global-loader ${isGlobalLoading ? 'visible' : ''}`}
      >
        <div className="global-loader-bar" />
      </div>
      <Routes>
        <Route element={<LoginPage />} path="/login" />
        <Route element={<RequireAuth />}>
          <Route element={<Shell />}>
            <Route element={lazyRoute(<DashboardPage />)} index />
            <Route element={lazyRoute(<SearchPage />)} path="search" />
            <Route
              element={lazyRoute(<ScanDetailPage />)}
              path="scans/:scanId"
            />
            <Route element={lazyRoute(<ScansPage />)} path="scans" />
            <Route element={lazyRoute(<DashboardPage />)} path="dashboard" />
            <Route element={lazyRoute(<HostPage />)} path="hosts/:ip" />
            <Route
              element={lazyRoute(<PivotPage />)}
              path="pivot/:kind/:value"
            />
            <Route
              element={lazyRoute(<SavedSearchesPage />)}
              path="saved-searches"
            />
            <Route element={lazyRoute(<AlertsPage />)} path="alerts" />
            <Route
              element={
                <RequireRole role="admin">
                  {lazyRoute(<RiskPolicyPage />)}
                </RequireRole>
              }
              path="risk/policies"
            />
            <Route
              element={lazyRoute(<AttackPathPage />)}
              path="attack-paths/:ip"
            />
            <Route
              element={lazyRoute(<ScanSchedulesPage />)}
              path="scan-schedules"
            />
            <Route
              element={
                <RequireRole role="admin">
                  {lazyRoute(<UsersPage />)}
                </RequireRole>
              }
              path={MANAGE_USERS_PATH.slice(1)}
            />
            <Route
              element={
                <RequireRole role="admin">
                  {lazyRoute(<AuditPage />)}
                </RequireRole>
              }
              path={MANAGE_AUDIT_PATH.slice(1)}
            />
            <Route element={<AccessDeniedPage />} path="access-denied" />
            <Route element={<Navigate to="/" />} path="*" />
          </Route>
        </Route>
      </Routes>
    </>
  );
}
