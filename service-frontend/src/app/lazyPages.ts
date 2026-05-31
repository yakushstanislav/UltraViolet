import { lazy, type ComponentType, type LazyExoticComponent } from 'react';

import { lazyImport } from '@helpers/lazyImport';

function lazyPage<M, K extends keyof M>(
  loader: () => Promise<M>,
  exportName: K
): LazyExoticComponent<ComponentType<unknown>> {
  return lazy(() =>
    lazyImport(loader).then((module) => ({
      default: module[exportName] as ComponentType<unknown>,
    }))
  );
}

export const AlertsPage = lazyPage(
  () => import('@features/Alerts/AlertsPage'),
  'AlertsPage'
);
export const DashboardPage = lazyPage(
  () => import('@features/Dashboard/DashboardPage'),
  'DashboardPage'
);
export const HostPage = lazyPage(
  () => import('@features/Host/HostPage'),
  'HostPage'
);
export const SavedSearchesPage = lazyPage(
  () => import('@features/SavedSearches/SavedSearchesPage'),
  'SavedSearchesPage'
);
export const ScanDetailPage = lazyPage(
  () => import('@features/Scans/ScanDetailPage'),
  'ScanDetailPage'
);
export const ScansPage = lazyPage(
  () => import('@features/Scans/ScansPage'),
  'ScansPage'
);
export const ScanSchedulesPage = lazyPage(
  () => import('@features/ScanSchedules/ScanSchedulesPage'),
  'ScanSchedulesPage'
);
export const UsersPage = lazyPage(
  () => import('@features/Admin/UsersPage'),
  'UsersPage'
);
export const AuditPage = lazyPage(
  () => import('@features/Admin/AuditPage'),
  'AuditPage'
);
export const SearchPage = lazyPage(
  () => import('@features/Search/SearchPage'),
  'SearchPage'
);
export const PivotPage = lazyPage(
  () => import('@features/Pivot/PivotPage'),
  'PivotPage'
);
export const RiskPolicyPage = lazyPage(
  () => import('@features/RiskPolicy/RiskPolicyPage'),
  'RiskPolicyPage'
);
export const AttackPathPage = lazyPage(
  () => import('@features/AttackPaths/AttackPathPage'),
  'AttackPathPage'
);
