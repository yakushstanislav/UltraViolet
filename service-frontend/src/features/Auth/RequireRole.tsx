import type { ReactNode } from 'react';

import { AccessDeniedPage } from './AccessDeniedPage';
import { useHasRole } from './hooks';
import type { AppRole } from '@/types/users';

type RequireRoleProps = {
  role: AppRole;
  children: ReactNode;
};

export function RequireRole({ role, children }: RequireRoleProps) {
  const allowed = useHasRole(role);

  if (!allowed) {
    return <AccessDeniedPage />;
  }

  return children;
}
