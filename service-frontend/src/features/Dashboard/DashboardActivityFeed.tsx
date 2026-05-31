import {
  Bell,
  CheckCircle2,
  History,
  Layers,
  PlayCircle,
  XCircle,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { EmptyState } from '@components/EmptyState';
import { useRealtimeEvents } from '@hooks/useRealtimeEvents';
import type {
  AlertFiredEventData,
  ScanStatusEventData,
} from '@/types/realtime';

const MAX_ITEMS = 40;

type ActivityKind =
  | 'scan-started'
  | 'scan-finished'
  | 'scan-failed'
  | 'scan-canceled'
  | 'scan-delta'
  | 'alert';

type ActivityItem = {
  id: string;
  ts: number;
  kind: ActivityKind;
  icon: LucideIcon;
  tone: 'neutral' | 'ok' | 'danger' | 'warning' | 'running';
  message: string;
  href?: string;
};

function formatRelative(now: number, ts: number): string {
  const diff = Math.max(0, Math.round((now - ts) / 1000));

  if (diff < 5) {
    return 'now';
  }

  if (diff < 60) {
    return `${diff.toString()}s`;
  }

  const min = Math.floor(diff / 60);
  if (min < 60) {
    return `${min.toString()}m`;
  }

  const hr = Math.floor(min / 60);
  if (hr < 24) {
    return `${hr.toString()}h`;
  }

  return `${Math.floor(hr / 24).toString()}d`;
}

export function DashboardActivityFeed() {
  const { t } = useTranslation();
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [now, setNow] = useState(() => Date.now());

  const push = useCallback((item: ActivityItem) => {
    setItems((current) => [item, ...current].slice(0, MAX_ITEMS));
  }, []);

  useRealtimeEvents(['scan.status', 'scan.delta', 'alert.fired'], (event) => {
    const ts = Date.parse(event.ts);
    const safeTs = Number.isNaN(ts) ? Date.now() : ts;
    const scanId = event.scan_id;

    if (event.type === 'scan.status' && scanId !== undefined) {
      const data = event.data as ScanStatusEventData;
      const status = data.status.toUpperCase();
      const href = `/scans/${scanId.toString()}`;

      if (status === 'RUNNING' || status === 'PENDING') {
        push({
          id: `${event.ts}-${scanId.toString()}-running`,
          ts: safeTs,
          kind: 'scan-started',
          icon: PlayCircle,
          tone: 'running',
          message: t('dashboard.activityScanStarted', { id: scanId }),
          href,
        });

        return;
      }

      if (status === 'DONE' || status === 'COMPLETED') {
        push({
          id: `${event.ts}-${scanId.toString()}-done`,
          ts: safeTs,
          kind: 'scan-finished',
          icon: CheckCircle2,
          tone: 'ok',
          message: t('dashboard.activityScanFinished', { id: scanId }),
          href,
        });

        return;
      }

      if (status === 'FAILED' || status === 'ERROR') {
        push({
          id: `${event.ts}-${scanId.toString()}-failed`,
          ts: safeTs,
          kind: 'scan-failed',
          icon: XCircle,
          tone: 'danger',
          message: t('dashboard.activityScanFailed', { id: scanId }),
          href,
        });

        return;
      }

      if (status === 'CANCELED' || status === 'CANCELLED') {
        push({
          id: `${event.ts}-${scanId.toString()}-canceled`,
          ts: safeTs,
          kind: 'scan-canceled',
          icon: XCircle,
          tone: 'warning',
          message: t('dashboard.activityScanCanceled', { id: scanId }),
          href,
        });

        return;
      }
    }

    if (event.type === 'scan.delta' && scanId !== undefined) {
      push({
        id: `${event.ts}-${scanId.toString()}-delta`,
        ts: safeTs,
        kind: 'scan-delta',
        icon: Layers,
        tone: 'neutral',
        message: t('dashboard.activityScanDelta', { id: scanId }),
        href: `/scans/${scanId.toString()}`,
      });

      return;
    }

    if (event.type === 'alert.fired') {
      const data = event.data as AlertFiredEventData;

      push({
        id: `${event.ts}-alert-${data.alert_rule_id.toString()}`,
        ts: safeTs,
        kind: 'alert',
        icon: Bell,
        tone: 'danger',
        message: t('dashboard.activityAlertFired', {
          name: data.name,
          hits: data.hits_count,
        }),
        href: '/alerts',
      });
    }
  });

  useEffect(() => {
    const id = window.setInterval(() => {
      setNow(Date.now());
    }, 30_000);

    return () => {
      window.clearInterval(id);
    };
  }, []);

  return (
    <section
      aria-label={t('dashboard.activityTitle')}
      className="dashboard-panel dashboard-activity"
    >
      <header className="dashboard-panel-header">
        <h2 className="dashboard-panel-title">
          {t('dashboard.activityTitle')}
        </h2>
      </header>
      {items.length === 0 ? (
        <EmptyState
          icon={<History aria-hidden size={20} />}
          title={t('dashboard.activityEmpty')}
        />
      ) : (
        <ol className="dashboard-activity-list">
          {items.map((item) => {
            const Icon = item.icon;
            const inner = (
              <>
                <span
                  aria-hidden
                  className={`dashboard-activity-icon dashboard-activity-icon-${item.tone}`}
                >
                  <Icon size={14} />
                </span>
                <span className="dashboard-activity-message">
                  {item.message}
                </span>
                <span className="dashboard-activity-time">
                  {formatRelative(now, item.ts)}
                </span>
              </>
            );

            return (
              <li className="dashboard-activity-row" key={item.id}>
                {item.href !== undefined ? (
                  <Link className="dashboard-activity-link" to={item.href}>
                    {inner}
                  </Link>
                ) : (
                  <span className="dashboard-activity-link">{inner}</span>
                )}
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

