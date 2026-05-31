import { useTranslation } from 'react-i18next';

import { useRealtimeConnection } from '@hooks/useRealtimeConnection';

type RealtimePanelBadgeProps = {
  labelKey?: string;
};

export function RealtimePanelBadge({
  labelKey = 'realtime.panelLive',
}: RealtimePanelBadgeProps) {
  const { t } = useTranslation();
  const state = useRealtimeConnection();

  if (state !== 'connected') {
    return null;
  }

  return (
    <span className="realtime-panel-badge">
      <span aria-hidden className="realtime-panel-badge-dot" />
      {t(labelKey)}
    </span>
  );
}
