import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';

export function AppDocumentI18n() {
  const { t, i18n } = useTranslation();

  useEffect(() => {
    document.documentElement.lang = i18n.language;
    document.title = t('app.title');
  }, [t, i18n.language]);

  return null;
}
