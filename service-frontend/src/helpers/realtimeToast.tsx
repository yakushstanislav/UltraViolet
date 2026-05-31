import { Bell, ChevronRight } from 'lucide-react';
import type { TFunction } from 'i18next';
import { toast } from 'sonner';
import { Link } from 'react-router-dom';

import type { AlertFiredEventData } from '@/types/realtime';

export function showAlertFiredToast(
  data: AlertFiredEventData,
  t: TFunction,
): void {
  const name = data.name || `#${String(data.alert_rule_id)}`;

  toast.custom(
    (toastId) => (
      <div className="realtime-toast">
        <span aria-hidden className="realtime-toast-icon">
          <Bell size={18} strokeWidth={2} />
        </span>
        <div className="realtime-toast-body">
          <span className="realtime-toast-eyebrow">
            {t('realtime.alertToastEyebrow')}
          </span>
          <strong className="realtime-toast-title">{name}</strong>
          <p className="realtime-toast-meta">
            {t('realtime.alertToastHits', { count: data.hits_count })}
          </p>
        </div>
        <Link
          className="realtime-toast-action"
          onClick={() => toast.dismiss(toastId)}
          to="/alerts"
        >
          {t('realtime.alertToastAction')}
          <ChevronRight aria-hidden size={14} />
        </Link>
      </div>
    ),
    {
      duration: 7000,
      className: 'realtime-toast-host',
    },
  );
}
