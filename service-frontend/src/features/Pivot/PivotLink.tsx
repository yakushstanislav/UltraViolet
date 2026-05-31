import { GitBranchPlus } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { pivotPath } from './pivotHelpers';

type PivotLinkProps = {
  kind: string;
  value: string;
};

export function PivotLink({ kind, value }: PivotLinkProps) {
  const { t } = useTranslation();

  if (!value) {
    return null;
  }

  return (
    <Link
      aria-label={t('hostPage.pivotOn')}
      className="pivot-link"
      title={t('hostPage.pivotOn')}
      to={pivotPath(kind, value)}
    >
      <GitBranchPlus aria-hidden size={13} />
    </Link>
  );
}
