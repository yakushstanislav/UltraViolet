import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { useAppSelector } from '@store/store';

export function RequireAuth() {
  const { t } = useTranslation();
  const { role, loading } = useAppSelector((state) => state.auth);
  const location = useLocation();

  if (loading) {
    return (
      <section className="page">
        <div className="notice">{t('auth.authorizing')}</div>
      </section>
    );
  }

  if (role === null) {
    return <Navigate replace state={{ from: location }} to="/login" />;
  }

  return <Outlet />;
}
