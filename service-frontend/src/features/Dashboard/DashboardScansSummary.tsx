import { Clock, Clock3, Layers, Minus, Plus, RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { DashboardWidgetTools } from '@components/DashboardWidgetTools';
import { EmptyState } from '@components/EmptyState';
import { RealtimePanelBadge } from '@components/RealtimePanelBadge';
import { RealtimeSyncBanner } from '@components/RealtimeSyncBanner';
import { useRealtimeEvents } from '@hooks/useRealtimeEvents';
import { getDashboardScansSummary } from '@services/DashboardAPI';
import type { ScanStatusEventData } from '@/types/realtime';
import type { DashboardScansSummaryResponse } from '@/types/api';

function formatDuration(
  seconds: number | undefined,
  translate: TFunction
): string {
  if (seconds === undefined || Number.isNaN(seconds)) {
    return translate('common.dash');
  }

  if (seconds < 1) {
    return translate('dashboard.durLt1s');
  }

  if (seconds < 60) {
    return `${Math.floor(seconds).toString()}s`;
  }

  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);

  if (m < 60) {
    return s === 0 ? `${m.toString()}m` : `${m.toString()}m ${s.toString()}s`;
  }

  const h = Math.floor(m / 60);
  const rem = m % 60;

  return rem === 0 ? `${h.toString()}h` : `${h.toString()}h ${rem.toString()}m`;
}

function formatRate(rate: number | undefined, translate: TFunction): string {
  if (rate === undefined || Number.isNaN(rate)) {
    return translate('common.dash');
  }

  return `${(rate * 100).toFixed(1)}%`;
}

function scanStatusTone(status: string): string {
  const normalized = status.toUpperCase();

  if (normalized === 'DONE' || normalized === 'COMPLETED') {
    return 'ok';
  }

  if (normalized === 'FAILED' || normalized === 'ERROR') {
    return 'danger';
  }

  if (normalized === 'CANCELED' || normalized === 'CANCELLED') {
    return 'muted';
  }

  if (normalized === 'RUNNING') {
    return 'running';
  }

  if (normalized === 'PAUSED') {
    return 'warning';
  }

  return 'neutral';
}

export function DashboardScansSummary() {
  const { t } = useTranslation();
  const [data, setData] = useState<DashboardScansSummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [liveSyncActive, setLiveSyncActive] = useState(false);
  const liveSyncHideRef = useRef<number | null>(null);
  const reloadDebounceRef = useRef<number | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await getDashboardScansSummary();
      setData(res);
      setLastUpdated(new Date());
    } catch (err: unknown) {
      setData(null);
      setError(
        err instanceof Error
          ? err.message
          : t('dashboard.scansSummaryLoadFailed')
      );
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  useEffect(() => {
    return () => {
      if (reloadDebounceRef.current !== null) {
        window.clearTimeout(reloadDebounceRef.current);
      }

      if (liveSyncHideRef.current !== null) {
        window.clearTimeout(liveSyncHideRef.current);
      }
    };
  }, []);

  const scheduleReload = useCallback(() => {
    setLiveSyncActive(true);

    if (liveSyncHideRef.current !== null) {
      window.clearTimeout(liveSyncHideRef.current);
    }

    liveSyncHideRef.current = window.setTimeout(() => {
      liveSyncHideRef.current = null;
      setLiveSyncActive(false);
    }, 1800);

    if (reloadDebounceRef.current !== null) {
      window.clearTimeout(reloadDebounceRef.current);
    }

    reloadDebounceRef.current = window.setTimeout(() => {
      reloadDebounceRef.current = null;
      void reload();
    }, 1000);
  }, [reload]);

  useRealtimeEvents(['scan.status', 'scan.delta'], (event) => {
    if (event.type === 'scan.status') {
      const payload = event.data as ScanStatusEventData;

      if (
        payload.status === 'DONE' ||
        payload.status === 'FAILED' ||
        payload.status === 'CANCELED' ||
        payload.status === 'RUNNING' ||
        payload.status === 'PENDING'
      ) {
        scheduleReload();
      }
    }

    if (event.type === 'scan.delta') {
      scheduleReload();
    }
  });

  const recent = data?.recent ?? [];

  return (
    <section
      aria-label={t('dashboard.scansSummaryAria')}
      className="dashboard-panel dashboard-scans-summary"
    >
      <header className="dashboard-panel-header">
        <h2 className="dashboard-panel-title">
          {t('dashboard.scansSummaryTitle')}
          <RealtimePanelBadge />
        </h2>
        <DashboardWidgetTools
          lastUpdated={lastUpdated}
          loading={loading}
          onRefresh={() => void reload()}
        />
      </header>
      <RealtimeSyncBanner
        active={liveSyncActive}
        messageKey="realtime.syncingScansBanner"
      />
      {error && <div className="error">{error}</div>}
      {loading && !data && <div className="dashboard-panel-skeleton" />}
      {!loading && data && (
        <>
          <div className="dashboard-scans-kpis">
            <div className="dashboard-scans-kpi">
              <span className="dashboard-scans-kpi-label">
                {t('dashboard.scansKpiAvgDuration')}
              </span>
              <strong className="dashboard-scans-kpi-value">
                {formatDuration(data.avg_duration_sec, t)}
              </strong>
            </div>
            <div className="dashboard-scans-kpi">
              <span className="dashboard-scans-kpi-label">
                {t('dashboard.scansKpiMedian')}
              </span>
              <strong className="dashboard-scans-kpi-value">
                {formatDuration(data.median_duration_sec, t)}
              </strong>
            </div>
            <div className="dashboard-scans-kpi">
              <span className="dashboard-scans-kpi-label">
                {t('dashboard.scansKpiSuccess7d')}
              </span>
              <strong className="dashboard-scans-kpi-value">
                {formatRate(data.success_rate_7d, t)}
              </strong>
            </div>
          </div>
          {recent.length === 0 ? (
            <EmptyState
              icon={<Clock aria-hidden size={20} />}
              title={t('dashboard.scansEmptyRecent')}
            />
          ) : (
            <ul className="dashboard-scans-list">
              {recent.map((scan) => {
                const tone = scanStatusTone(scan.status);
                const scanLabel = scan.name ?? `#${String(scan.scan_id)}`;

                return (
                  <li className="dashboard-scans-row" key={scan.scan_id}>
                    <div className="dashboard-scans-row-main">
                      <Link
                        className="dashboard-scans-row-link"
                        to={`/scans/${String(scan.scan_id)}`}
                      >
                        {scanLabel}
                      </Link>
                      <span
                        className={`dashboard-scans-status dashboard-scans-status-${tone}`}
                      >
                        {scan.status}
                      </span>
                    </div>
                    <div className="dashboard-scans-row-stats">
                      <span
                        className="dashboard-scans-stat"
                        title={t('dashboard.scansStatDurationTitle')}
                      >
                        <Clock3 size={12} />
                        {formatDuration(scan.duration_sec, t)}
                      </span>
                      <span
                        className="dashboard-scans-stat"
                        title={t('dashboard.scansStatServicesTitle')}
                      >
                        <Layers size={12} />
                        {scan.services_found.toLocaleString()}
                      </span>
                      <span
                        className="dashboard-scans-delta dashboard-scans-delta-new"
                        title={t('dashboard.scansStatNewTitle')}
                      >
                        <Plus size={11} />
                        {scan.new_services.toLocaleString()}
                      </span>
                      <span
                        className="dashboard-scans-delta dashboard-scans-delta-gone"
                        title={t('dashboard.scansStatGoneTitle')}
                      >
                        <Minus size={11} />
                        {scan.disappeared_services.toLocaleString()}
                      </span>
                      <span
                        className="dashboard-scans-delta dashboard-scans-delta-changed"
                        title={t('dashboard.scansStatChangedTitle')}
                      >
                        <RefreshCw size={11} />
                        {scan.changed_services.toLocaleString()}
                      </span>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </>
      )}
    </section>
  );
}
