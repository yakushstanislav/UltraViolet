import { useTranslation } from 'react-i18next';

import { useRealtimeConnection } from '@hooks/useRealtimeConnection';

export function RealtimeConnectionPill() {
  const { t } = useTranslation();
  const state = useRealtimeConnection();

  if (state === 'disconnected') {
    return null;
  }

  const label =
    state === 'connected'
      ? t('realtime.connectionLive')
      : state === 'reconnecting'
        ? t('realtime.connectionReconnecting')
        : t('realtime.connectionConnecting');

  return (
    <span
      aria-live="polite"
      className={`realtime-connection-pill realtime-connection-pill-${state}`}
      title={label}
    >
      <span aria-hidden className="realtime-connection-dot" />
      <span className="realtime-connection-label">{label}</span>
    </span>
  );
}
