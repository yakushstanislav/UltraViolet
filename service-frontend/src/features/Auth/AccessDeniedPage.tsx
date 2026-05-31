import { Trans, useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

export function AccessDeniedPage() {
  const { t } = useTranslation();

  return (
    <section className="page access-denied-page">
      <div className="page-header">
        <div>
          <h1>{t('auth.accessDeniedTitle')}</h1>
          <p>{t('auth.accessDeniedBody')}</p>
        </div>
      </div>
      <div className="panel access-denied-panel">
        <p>
          <Trans
            components={{
              searchLink: <Link to="/search" />,
              dashboardLink: <Link to="/dashboard" />,
            }}
            i18nKey="auth.accessDeniedLinks"
          />
        </p>
        <p className="access-denied-hint">{t('auth.accessDeniedHint')}</p>
      </div>
    </section>
  );
}
