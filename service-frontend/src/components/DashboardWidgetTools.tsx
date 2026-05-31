import { RefreshCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { formatDate } from '@helpers/format';

type DashboardWidgetToolsProps = {
  lastUpdated: Date | null;
  loading?: boolean;
  onRefresh: () => void;
};

export function DashboardWidgetTools({
  lastUpdated,
  loading = false,
  onRefresh,
}: DashboardWidgetToolsProps) {
  const { t } = useTranslation();

  const updatedLabel =
    lastUpdated !== null
      ? t('dashboard.lastUpdated', {
          time: formatDate(lastUpdated.toISOString()),
        })
      : t('dashboard.notUpdatedYet');

  return (
    <div className="dashboard-widget-tools">
      <button
        aria-busy={loading}
        aria-label={updatedLabel}
        className="secondary dashboard-widget-refresh"
        disabled={loading}
        onClick={onRefresh}
        title={updatedLabel}
        type="button"
      >
        <RefreshCw
          aria-hidden
          className={loading ? 'spin' : undefined}
          size={14}
        />
      </button>
    </div>
  );
}
