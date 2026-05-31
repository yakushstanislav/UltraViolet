import { Radio } from 'lucide-react';
import { useTranslation } from 'react-i18next';

type RealtimeSyncBannerProps = {
  active: boolean;
  messageKey?: string;
};

export function RealtimeSyncBanner({
  active,
  messageKey = 'realtime.syncingBanner',
}: RealtimeSyncBannerProps) {
  const { t } = useTranslation();

  if (!active) {
    return null;
  }

  return (
    <div aria-live="polite" className="realtime-sync-banner" role="status">
      <span aria-hidden className="realtime-sync-banner-icon">
        <Radio size={15} strokeWidth={2} />
      </span>
      <span className="realtime-sync-banner-text">{t(messageKey)}</span>
      <span aria-hidden className="realtime-sync-banner-shimmer" />
    </div>
  );
}
