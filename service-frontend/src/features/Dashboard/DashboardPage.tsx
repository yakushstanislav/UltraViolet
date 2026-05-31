import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Bell,
  CheckCircle2,
  Clock3,
  CloudDownload,
  Database,
  Globe,
  Layers,
  PauseCircle,
  Plus,
  Search,
  ShieldAlert,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
} from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Link } from 'react-router-dom';
import { RealtimeSyncBanner } from '@components/RealtimeSyncBanner';
import { Tooltip } from '@components/Tooltip';
import { showAlertFiredToast } from '@helpers/realtimeToast';
import { useRealtimeEvents } from '@hooks/useRealtimeEvents';
import { getDashboardMap } from '@services/DashboardAPI';
import { getCVESyncStatus } from '@services/CVEAPI';
import { useAppDispatch, useAppSelector } from '@store/store';
import type {
  CVESyncStatusResponse,
  DashboardMapResponse,
  DashboardStats,
  DashboardTrendsRange,
} from '@/types/api';
import { LazyDashboardHostMap } from '@components/maps/LazyDashboardHostMap';
import { DashboardActivityFeed } from './DashboardActivityFeed';
import { DashboardRiskWidget } from './DashboardRiskWidget';
import { DashboardScansSummary } from './DashboardScansSummary';
import { DashboardTopCVEs } from './DashboardTopCVEs';
import { DashboardTopLists } from './DashboardTopLists';
import { DashboardTrendsChart } from './DashboardTrendsChart';
import type {
  AlertFiredEventData,
  ScanStatusEventData,
} from '@/types/realtime';
import { loadDashboard } from './dashboardActions';
import { resetDashboard } from './dashboardSlice';

type KpiTone = 'neutral' | 'running' | 'ok' | 'danger' | 'warning';

type KpiAnomaly = {
  direction: 'up' | 'down';
  multiplier: number;
};

type QueueStatKey = 'pending' | 'running' | 'paused' | 'done' | 'failed';

type QueueStatConfig = {
  key: QueueStatKey;
  label: string;
  tone: KpiTone;
  icon: LucideIcon;
  to: string;
};

const emptyMapCountries: DashboardMapResponse['countries'] = [];
const emptyMapPoints: DashboardMapResponse['points'] = [];

function makeQueueStats(translate: TFunction): QueueStatConfig[] {
  return [
    {
      key: 'pending',
      label: translate('dashboard.queueQueued'),
      tone: 'neutral',
      icon: Clock3,
      to: '/scans?status=pending',
    },
    {
      key: 'running',
      label: translate('dashboard.queueActive'),
      tone: 'running',
      icon: Activity,
      to: '/scans?status=running',
    },
    {
      key: 'paused',
      label: translate('dashboard.queuePaused'),
      tone: 'warning',
      icon: PauseCircle,
      to: '/scans?status=paused',
    },
    {
      key: 'done',
      label: translate('dashboard.queueCompleted'),
      tone: 'ok',
      icon: CheckCircle2,
      to: '/scans?status=done',
    },
    {
      key: 'failed',
      label: translate('dashboard.queueFaulted'),
      tone: 'danger',
      icon: AlertTriangle,
      to: '/scans?status=failed',
    },
  ];
}

function formatDashboardRelative(diffMs: number, translate: TFunction): string {
  const sec = Math.max(0, Math.round(diffMs / 1000));

  if (sec < 10) {
    return translate('dashboard.relativeJustNow');
  }

  if (sec < 60) {
    return translate('dashboard.relativeSecondsAgo', { count: sec });
  }

  const min = Math.round(sec / 60);

  if (min < 60) {
    return translate('dashboard.relativeMinutesAgo', { count: min });
  }

  const hr = Math.round(min / 60);

  if (hr < 24) {
    return translate('dashboard.relativeHoursAgo', { count: hr });
  }

  return translate('dashboard.relativeDaysAgo', { count: Math.round(hr / 24) });
}

function formatDashboardRelativeISO(
  iso: string | null | undefined,
  translate: TFunction
): string | null {
  if (!iso) {
    return null;
  }

  const ts = Date.parse(iso);

  if (Number.isNaN(ts)) {
    return null;
  }

  return formatDashboardRelative(Date.now() - ts, translate);
}

type StatusStripCta = {
  to: string;
  label: string;
};

type StatusStrip = {
  kind: 'critical';
  summary: string;
  cta: StatusStripCta | null;
};

function deriveStatusStrip(
  data: DashboardStats | null,
  translate: TFunction,
): StatusStrip | null {
  if (!data) {
    return null;
  }

  const issues: string[] = [];
  let cta: StatusStripCta | null = null;

  const alertsActive = data.alerts_active ?? 0;
  const scansFaulted = data.failed ?? 0;

  if (alertsActive > 0) {
    issues.push(
      translate('dashboard.statusAlertsActive', {
        count: alertsActive,
      }),
    );
    cta = {
      to: '/alerts',
      label: translate('dashboard.statusViewAlerts'),
    };
  }

  if (scansFaulted > 0) {
    issues.push(
      translate('dashboard.statusScansFaulted', { count: scansFaulted }),
    );
    if (cta === null) {
      cta = {
        to: '/scans?status=failed',
        label: translate('dashboard.statusViewScans'),
      };
    }
  }

  if (issues.length > 0) {
    return {
      kind: 'critical',
      summary: issues.join(' · '),
      cta,
    };
  }

  return null;
}

function computeScansAnomaly(
  data: DashboardStats | null,
): KpiAnomaly | null {
  if (!data) {
    return null;
  }

  const weekly = data.scans_7d ?? 0;

  if (weekly < 7) {
    return null;
  }

  const baseline = weekly / 7;

  if (baseline < 1) {
    return null;
  }

  const ratio = (data.scans_24h ?? 0) / baseline;

  if (ratio >= 2) {
    return { direction: 'up', multiplier: ratio };
  }

  if (ratio > 0 && ratio <= 0.5) {
    return { direction: 'down', multiplier: ratio };
  }

  return null;
}

type DeltaChipProps = {
  delta: number;
};

function DeltaChip({ delta }: DeltaChipProps) {
  if (delta === 0) {
    return null;
  }

  const direction = delta > 0 ? 'up' : 'down';
  const Icon = direction === 'up' ? ArrowUp : ArrowDown;

  return (
    <span className={`dashboard-kpi-delta dashboard-kpi-delta-${direction}`}>
      <Icon size={11} />
      {Math.abs(delta).toLocaleString()}
    </span>
  );
}

type KpiProps = {
  label: string;
  icon: LucideIcon;
  tone: KpiTone;
  value: number;
  to?: string;
  delta?: number;
  meta?: string;
  alert?: boolean;
  changed?: boolean;
  tooltip?: string;
  anomaly?: KpiAnomaly | null;
};

function Kpi({
  label,
  icon: Icon,
  tone,
  value,
  to,
  delta,
  meta,
  alert,
  changed,
  tooltip,
  anomaly,
}: KpiProps) {
  const { t } = useTranslation();
  const quiet = value === 0 && !alert;
  const loud = !quiet && (tone === 'danger' || tone === 'warning');

  const className = [
    'dashboard-kpi',
    `dashboard-kpi-${tone}`,
    alert ? 'dashboard-kpi-alert' : null,
    changed ? 'dashboard-kpi-changed' : null,
    quiet ? 'dashboard-kpi-quiet' : null,
    loud ? 'dashboard-kpi-loud' : null,
  ]
    .filter(Boolean)
    .join(' ');

  const anomalyMultiplier =
    anomaly !== null && anomaly !== undefined
      ? anomaly.multiplier >= 10
        ? Math.round(anomaly.multiplier)
        : Math.round(anomaly.multiplier * 10) / 10
      : null;

  const labelNode =
    tooltip !== undefined && tooltip !== '' ? (
      <Tooltip label={tooltip}>
        <span className="dashboard-kpi-label">{label}</span>
      </Tooltip>
    ) : (
      <span className="dashboard-kpi-label">{label}</span>
    );

  const content = (
    <>
      <div className="dashboard-kpi-top">
        {labelNode}
        <Icon size={15} />
      </div>
      <strong className="dashboard-kpi-value">{value.toLocaleString()}</strong>
      {anomaly !== null && anomaly !== undefined && (
        <span
          className={`dashboard-kpi-anomaly dashboard-kpi-anomaly-${anomaly.direction}`}
        >
          {anomaly.direction === 'up' ? (
            <TrendingUp size={11} aria-hidden />
          ) : (
            <TrendingDown size={11} aria-hidden />
          )}
          {t('dashboard.anomalyVs7dAvg', {
            multiplier: anomalyMultiplier ?? 0,
          })}
        </span>
      )}
      {delta !== undefined && delta !== 0 && <DeltaChip delta={delta} />}
      {meta && <span className="dashboard-kpi-meta">{meta}</span>}
    </>
  );

  if (to) {
    return (
      <Link className={className} to={to}>
        {content}
      </Link>
    );
  }

  return <div className={className}>{content}</div>;
}

function KpiSkeletons({ count }: { count: number }) {
  return (
    <>
      {Array.from({ length: count }, (_, idx) => (
        <div
          className="dashboard-kpi dashboard-kpi-skeleton"
          key={`skeleton-${idx}`}
        />
      ))}
    </>
  );
}

const RANGE_STORAGE_KEY = 'uv-dashboard-range';
const RANGE_VALUES: readonly DashboardTrendsRange[] = ['24h', '7d', '30d'];

function readStoredRange(): DashboardTrendsRange {
  if (typeof window === 'undefined') {
    return '7d';
  }

  const raw = window.localStorage.getItem(RANGE_STORAGE_KEY);
  if (raw === '24h' || raw === '7d' || raw === '30d') {
    return raw;
  }

  return '7d';
}

type DashboardTimeRangeProps = {
  value: DashboardTrendsRange;
  onChange: (next: DashboardTrendsRange) => void;
};

function DashboardTimeRange({ value, onChange }: DashboardTimeRangeProps) {
  const { t } = useTranslation();
  const labels: Record<DashboardTrendsRange, string> = {
    '24h': t('dashboard.trendsRange24h'),
    '7d': t('dashboard.trendsRange7d'),
    '30d': t('dashboard.trendsRange30d'),
  };

  const handleClick = (option: DashboardTrendsRange) => {
    return (event: ReactMouseEvent<HTMLButtonElement>) => {
      event.preventDefault();
      onChange(option);
    };
  };

  return (
    <div
      aria-label={t('dashboard.rangeAria')}
      className="dashboard-time-range"
    >
      {RANGE_VALUES.map((option) => {
        const active = option === value;

        return (
          <button
            aria-label={labels[option]}
            aria-pressed={active}
            className={`dashboard-time-range-item${active ? ' is-active' : ''}`}
            key={option}
            onClick={handleClick(option)}
            type="button"
          >
            {labels[option]}
          </button>
        );
      })}
    </div>
  );
}

export function DashboardPage() {
  const { t } = useTranslation();
  const dispatch = useAppDispatch();
  const { data, loading, error } = useAppSelector((state) => state.dashboard);
  const [previousData, setPreviousData] = useState<DashboardStats | null>(null);
  const lastDataRef = useRef<DashboardStats | null>(null);
  const [mapData, setMapData] = useState<DashboardMapResponse | null>(null);
  const [mapLoading, setMapLoading] = useState(true);
  const [mapError, setMapError] = useState<string | null>(null);
  const [nvdBootstrap, setNvdBootstrap] =
    useState<CVESyncStatusResponse | null>(null);

  const queueStats = useMemo(() => makeQueueStats(t), [t]);

  const [range, setRange] = useState<DashboardTrendsRange>(() =>
    readStoredRange(),
  );

  const handleRangeChange = useCallback((next: DashboardTrendsRange) => {
    setRange(next);
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(RANGE_STORAGE_KEY, next);
    }
  }, []);

  const refresh = useCallback(() => {
    void dispatch(loadDashboard());
  }, [dispatch]);

  const dashboardDebounceRef = useRef<number | null>(null);
  const mapRefreshDebounceRef = useRef<number | null>(null);
  const [liveSyncActive, setLiveSyncActive] = useState(false);
  const liveSyncHideRef = useRef<number | null>(null);

  const pulseLiveSync = useCallback(() => {
    setLiveSyncActive(true);

    if (liveSyncHideRef.current !== null) {
      window.clearTimeout(liveSyncHideRef.current);
    }

    liveSyncHideRef.current = window.setTimeout(() => {
      liveSyncHideRef.current = null;
      setLiveSyncActive(false);
    }, 1800);
  }, []);

  const scheduleDashboardRefresh = useCallback(() => {
    pulseLiveSync();

    if (dashboardDebounceRef.current !== null) {
      window.clearTimeout(dashboardDebounceRef.current);
    }

    dashboardDebounceRef.current = window.setTimeout(() => {
      dashboardDebounceRef.current = null;
      refresh();
    }, 1000);
  }, [refresh, pulseLiveSync]);

  const scheduleMapRefresh = useCallback(() => {
    pulseLiveSync();

    if (mapRefreshDebounceRef.current !== null) {
      window.clearTimeout(mapRefreshDebounceRef.current);
    }

    mapRefreshDebounceRef.current = window.setTimeout(() => {
      mapRefreshDebounceRef.current = null;

      void getDashboardMap()
        .then((res) => {
          setMapData(res);
          setMapError(null);
        })
        .catch((err: unknown) => {
          setMapData(null);
          setMapError(
            err instanceof Error ? err.message : t('dashboard.mapLoadFailed')
          );
        });
    }, 1000);
  }, [t, pulseLiveSync]);

  useRealtimeEvents(['scan.status', 'scan.delta', 'alert.fired'], (event) => {
    if (event.type === 'alert.fired') {
      const data = event.data as AlertFiredEventData;
      showAlertFiredToast(data, t);
    }

    if (event.type === 'scan.status') {
      const data = event.data as ScanStatusEventData;
      if (
        data.status === 'DONE' ||
        data.status === 'FAILED' ||
        data.status === 'CANCELED'
      ) {
        scheduleDashboardRefresh();
        scheduleMapRefresh();
      } else if (data.status === 'RUNNING' || data.status === 'PENDING') {
        scheduleDashboardRefresh();
      }
    }

    if (event.type === 'scan.delta') {
      scheduleDashboardRefresh();
    }
  });

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;

    async function sleep(ms: number): Promise<void> {
      await new Promise<void>((resolve) => {
        const timer = window.setTimeout(() => {
          signal.removeEventListener('abort', onAbort);
          resolve();
        }, ms);

        const onAbort = () => {
          window.clearTimeout(timer);
          resolve();
        };

        signal.addEventListener('abort', onAbort, { once: true });
      });
    }

    async function pollLoop() {
      for (;;) {
        try {
          const s = await getCVESyncStatus(signal);
          if (signal.aborted) {
            return;
          }

          setNvdBootstrap(s);

          if (s.bootstrapped) {
            return;
          }
        } catch {
          if (signal.aborted) {
            return;
          }

          setNvdBootstrap(null);
        }

        await sleep(8000);

        if (signal.aborted) {
          return;
        }
      }
    }

    void pollLoop();

    return () => {
      controller.abort();
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();

    setMapLoading(true);
    setMapError(null);

    void getDashboardMap(controller.signal)
      .then((res) => {
        if (controller.signal.aborted) {
          return;
        }

        setMapData(res);
        setMapLoading(false);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        setMapData(null);
        setMapLoading(false);
        setMapError(
          err instanceof Error ? err.message : t('dashboard.mapLoadFailed')
        );
      });

    return () => {
      controller.abort();
    };
  }, [t]);

  useEffect(() => {
    if (!data) {
      return;
    }

    setPreviousData(lastDataRef.current);
    lastDataRef.current = data;
  }, [data]);

  useEffect(() => {
    return () => {
      if (dashboardDebounceRef.current !== null) {
        window.clearTimeout(dashboardDebounceRef.current);
      }

      if (mapRefreshDebounceRef.current !== null) {
        window.clearTimeout(mapRefreshDebounceRef.current);
      }

      if (liveSyncHideRef.current !== null) {
        window.clearTimeout(liveSyncHideRef.current);
      }

      dispatch(resetDashboard());
    };
  }, [dispatch]);

  const [, setNowTick] = useState(0);

  useEffect(() => {
    const id = window.setInterval(() => {
      setNowTick((current) => current + 1);
    }, 30_000);

    return () => {
      window.clearInterval(id);
    };
  }, []);

  const isInitialLoading = loading && !data;
  const showSkeleton = isInitialLoading;

  const mapCountries = mapData?.countries ?? emptyMapCountries;
  const mapPoints = mapData?.points ?? emptyMapPoints;

  const countriesCount = mapCountries.length;
  const lastScanRelative = formatDashboardRelativeISO(
    data?.last_scan_finished_at,
    t
  );

  const statusStrip = useMemo(
    () => deriveStatusStrip(data, t),
    [data, t],
  );

  const scansAnomaly = useMemo(() => computeScansAnomaly(data), [data]);

  const fieldChanged = (
    field:
      | 'hosts'
      | 'services'
      | 'scans_24h'
      | 'saved_searches'
      | 'alerts_active'
      | 'alerts_fired_24h'
      | 'hosts_with_critical_cve'
      | 'cve_critical'
      | 'change_events_7d_new'
      | 'change_events_7d_disappeared'
      | 'change_events_7d_changed',
  ): boolean => {
    if (!data || !previousData) {
      return false;
    }

    return (data[field] ?? 0) !== (previousData[field] ?? 0);
  };

  const scopeChips = useMemo(() => {
    if (!data) {
      return null;
    }

    const chips: { key: string; icon: LucideIcon; value: number; label: string }[] = [
      {
        key: 'hosts',
        icon: Database,
        value: data.hosts,
        label: t('dashboard.scopeHostsLabel', { count: data.hosts }),
      },
      {
        key: 'services',
        icon: Layers,
        value: data.services,
        label: t('dashboard.scopeServicesLabel', { count: data.services }),
      },
    ];

    if (countriesCount > 0) {
      chips.push({
        key: 'countries',
        icon: Globe,
        value: countriesCount,
        label: t('dashboard.scopeCountriesLabel', { count: countriesCount }),
      });
    }

    return chips;
  }, [data, countriesCount, t]);

  const lastScanFreshness = useMemo<
    'fresh' | 'recent' | 'stale' | null
  >(() => {
    if (!data?.last_scan_finished_at) {
      return null;
    }

    const ts = Date.parse(data.last_scan_finished_at);
    if (Number.isNaN(ts)) {
      return null;
    }

    const diffMin = (Date.now() - ts) / 60_000;
    if (diffMin < 60) {
      return 'fresh';
    }

    if (diffMin < 24 * 60) {
      return 'recent';
    }

    return 'stale';
  }, [data?.last_scan_finished_at]);

  const queueDelta = (key: QueueStatKey): number => {
    if (!data || !previousData) {
      return 0;
    }

    return (data[key] ?? 0) - (previousData[key] ?? 0);
  };

  const nvdBootstrapPct =
    nvdBootstrap !== null &&
    !nvdBootstrap.bootstrapped &&
    typeof nvdBootstrap.progress === 'number'
      ? Math.round(Math.min(1, Math.max(0, nvdBootstrap.progress)) * 100)
      : null;

  const nvdBootstrapEntries =
    nvdBootstrap !== null && !nvdBootstrap.bootstrapped
      ? {
          done: nvdBootstrap.entries_done,
          total: nvdBootstrap.entries_total,
        }
      : null;

  const nvdBootstrapStamp = (() => {
    if (!nvdBootstrapEntries) {
      return nvdBootstrapPct !== null
        ? `${nvdBootstrapPct}%`
        : t('common.ellipsis');
    }

    const { done, total } = nvdBootstrapEntries;

    if (typeof done === 'number' && typeof total === 'number') {
      return t('dashboard.nvdCvesProgress', {
        done: done.toLocaleString(),
        total: total.toLocaleString(),
      });
    }

    if (typeof done === 'number') {
      return t('dashboard.nvdCvesMirrored', { done: done.toLocaleString() });
    }

    return nvdBootstrapPct !== null
      ? `${nvdBootstrapPct}%`
      : t('common.ellipsis');
  })();

  return (
    <section className="page dashboard-layout">
      <header className="dashboard-header">
        <div className="dashboard-header-meta">
          <h1 className="dashboard-header-title">{t('dashboard.title')}</h1>
          {scopeChips && (
            <div className="dashboard-header-hero">
              {scopeChips.map((chip, idx) => (
                <span className="dashboard-header-stat" key={chip.key}>
                  {idx > 0 && (
                    <span
                      aria-hidden
                      className="dashboard-header-stat-sep"
                    />
                  )}
                  <chip.icon
                    aria-hidden
                    className="dashboard-header-stat-icon"
                    size={16}
                  />
                  <span className="dashboard-header-stat-value">
                    {chip.value.toLocaleString()}
                  </span>
                  <span className="dashboard-header-stat-label">
                    {chip.label}
                  </span>
                </span>
              ))}
            </div>
          )}
          {lastScanRelative && (
            <p className="dashboard-header-stamp">
              {lastScanFreshness && (
                <span
                  aria-hidden
                  className={`dashboard-header-stamp-dot dashboard-header-stamp-dot-${lastScanFreshness}`}
                />
              )}
              {t('dashboard.lastScan', { time: lastScanRelative })}
            </p>
          )}
        </div>
        <div className="dashboard-header-status">
          <DashboardTimeRange onChange={handleRangeChange} value={range} />
          <Link className="dashboard-header-action" to="/scans">
            <Plus size={14} />
            {t('dashboard.launchScan')}
          </Link>
          <Link className="dashboard-header-action" to="/search">
            <Search size={14} />
            {t('dashboard.query')}
          </Link>
        </div>
      </header>

      <RealtimeSyncBanner active={liveSyncActive} />

      {statusStrip && (
        <div
          aria-live="polite"
          className="dashboard-status-strip dashboard-status-strip-critical"
          role="status"
        >
          <span aria-hidden className="dashboard-status-strip-icon">
            <AlertOctagon size={16} />
          </span>
          <span className="dashboard-status-strip-summary">
            {statusStrip.summary}
          </span>
          {statusStrip.cta && (
            <Link
              className="dashboard-status-strip-cta"
              to={statusStrip.cta.to}
            >
              {statusStrip.cta.label}
            </Link>
          )}
        </div>
      )}

      {nvdBootstrap && !nvdBootstrap.bootstrapped && (
        <div aria-live="polite" className="dashboard-nvd-banner" role="status">
          <div className="dashboard-nvd-banner-main">
            <span className="dashboard-nvd-banner-label">
              <CloudDownload size={16} /> {t('dashboard.nvdLabel')}
            </span>
            <span className="dashboard-header-stamp">{nvdBootstrapStamp}</span>
          </div>
          <div className="dashboard-nvd-progress">
            <div
              aria-valuemax={100}
              aria-valuemin={0}
              aria-valuenow={nvdBootstrapPct ?? undefined}
              className="dashboard-nvd-progress-fill"
              role="progressbar"
              style={{
                width: nvdBootstrapPct !== null ? `${nvdBootstrapPct}%` : '4%',
              }}
            />
          </div>
          <p className="dashboard-nvd-banner-hint">{t('dashboard.nvdHint')}</p>
        </div>
      )}

      {error && <div className="error">{error}</div>}

      <section
        aria-label={t('dashboard.ariaInventory')}
        className="dashboard-group"
      >
        <h2 className="dashboard-group-title">
          {t('dashboard.groupInventory')}
        </h2>
        <div className="dashboard-grid dashboard-grid-4">
          {showSkeleton ? (
            <KpiSkeletons count={4} />
          ) : (
            <>
              <Kpi
                changed={fieldChanged('hosts')}
                icon={Database}
                label={t('dashboard.kpiHosts')}
                tone="neutral"
                tooltip={t('dashboard.tip.hosts')}
                value={data?.hosts ?? 0}
              />
              <Kpi
                changed={fieldChanged('services')}
                icon={Layers}
                label={t('dashboard.kpiServices')}
                tone="neutral"
                tooltip={t('dashboard.tip.services')}
                value={data?.services ?? 0}
              />
              <Kpi
                anomaly={scansAnomaly}
                changed={fieldChanged('scans_24h')}
                icon={Activity}
                label={t('dashboard.kpiScans24h')}
                tone="running"
                tooltip={t('dashboard.tip.scans24h')}
                value={data?.scans_24h ?? 0}
              />
              <Kpi
                changed={fieldChanged('saved_searches')}
                icon={Search}
                label={t('dashboard.kpiSavedSearches')}
                to="/saved-searches"
                tone="neutral"
                tooltip={t('dashboard.tip.savedSearches')}
                value={data?.saved_searches ?? 0}
              />
            </>
          )}
        </div>
      </section>

      <section aria-label={t('dashboard.ariaRisk')} className="dashboard-group">
        <h2 className="dashboard-group-title">{t('dashboard.groupRisk')}</h2>
        <div className="dashboard-grid dashboard-grid-4">
          {showSkeleton ? (
            <KpiSkeletons count={4} />
          ) : (
            <>
              <Kpi
                alert={(data?.alerts_active ?? 0) > 0}
                changed={fieldChanged('alerts_active')}
                icon={Bell}
                label={t('dashboard.kpiAlertsActive')}
                to="/alerts"
                tone={(data?.alerts_active ?? 0) > 0 ? 'danger' : 'neutral'}
                tooltip={t('dashboard.tip.alertsActive')}
                value={data?.alerts_active ?? 0}
              />
              <Kpi
                changed={fieldChanged('alerts_fired_24h')}
                icon={Bell}
                label={t('dashboard.kpiAlertsFired24h')}
                tone="neutral"
                tooltip={t('dashboard.tip.alertsFired24h')}
                value={data?.alerts_fired_24h ?? 0}
              />
              <Kpi
                alert={(data?.hosts_with_critical_cve ?? 0) > 0}
                changed={fieldChanged('hosts_with_critical_cve')}
                icon={ShieldAlert}
                label={t('dashboard.kpiCriticalCves')}
                to="/search?has_cve=true&cve_severity=CRITICAL"
                tone={
                  (data?.hosts_with_critical_cve ?? 0) > 0
                    ? 'danger'
                    : 'neutral'
                }
                tooltip={t('dashboard.tip.criticalCves')}
                value={data?.hosts_with_critical_cve ?? 0}
              />
              <Kpi
                alert={(data?.cve_critical ?? 0) > 0}
                changed={fieldChanged('cve_critical')}
                icon={ShieldAlert}
                label={t('dashboard.kpiCveMatches')}
                tone={(data?.cve_critical ?? 0) > 0 ? 'danger' : 'neutral'}
                tooltip={t('dashboard.tip.cveMatches')}
                value={data?.cve_critical ?? 0}
              />
            </>
          )}
        </div>
      </section>

      <section
        aria-label={t('dashboard.ariaOperations')}
        className="dashboard-group"
      >
        <h2 className="dashboard-group-title">{t('dashboard.groupOps')}</h2>
        <div className="dashboard-grid dashboard-grid-3">
          {showSkeleton ? (
            <KpiSkeletons count={3} />
          ) : (
            <>
              <Kpi
                changed={fieldChanged('change_events_7d_new')}
                icon={TrendingUp}
                label={t('dashboard.kpiNew7d')}
                tone="ok"
                tooltip={t('dashboard.tip.changeNew7d')}
                value={data?.change_events_7d_new ?? 0}
              />
              <Kpi
                changed={fieldChanged('change_events_7d_disappeared')}
                icon={TrendingDown}
                label={t('dashboard.kpiDisappeared7d')}
                tone="danger"
                tooltip={t('dashboard.tip.changeGone7d')}
                value={data?.change_events_7d_disappeared ?? 0}
              />
              <Kpi
                changed={fieldChanged('change_events_7d_changed')}
                icon={Activity}
                label={t('dashboard.kpiChanged7d')}
                tone="neutral"
                tooltip={t('dashboard.tip.change7d')}
                value={data?.change_events_7d_changed ?? 0}
              />
            </>
          )}
        </div>
        {showSkeleton ? (
          <div className="dashboard-queue-stripe dashboard-queue-stripe-skeleton" />
        ) : (
          <div className="dashboard-queue-stripe">
            {queueStats.map((stat) => {
              const value = data?.[stat.key] ?? 0;
              const delta = queueDelta(stat.key);
              const itemClass = [
                'dashboard-queue-stripe-item',
                `dashboard-queue-stripe-item-${stat.tone}`,
                delta !== 0 ? 'is-changed' : null,
              ]
                .filter(Boolean)
                .join(' ');

              return (
                <Link
                  className={itemClass}
                  key={stat.key}
                  title={stat.label}
                  to={stat.to}
                >
                  <span aria-hidden className="dashboard-queue-stripe-dot" />
                  <span className="dashboard-queue-stripe-label">
                    {stat.label}
                  </span>
                  <strong className="dashboard-queue-stripe-value">
                    {value.toLocaleString()}
                  </strong>
                  {delta !== 0 && <DeltaChip delta={delta} />}
                </Link>
              );
            })}
          </div>
        )}
      </section>

      <div className="dashboard-bento">
        <div className="dashboard-bento-cell dashboard-bento-cell-map">
          <LazyDashboardHostMap
            countries={mapCountries}
            error={mapError}
            loading={mapLoading}
            points={mapPoints}
            pointsSource={mapData?.points_source}
          />
        </div>
        <div className="dashboard-bento-cell dashboard-bento-cell-cves">
          <DashboardTopCVEs />
        </div>
        <div className="dashboard-bento-cell dashboard-bento-cell-trends">
          <DashboardTrendsChart range={range} />
        </div>
        <div className="dashboard-bento-cell dashboard-bento-cell-risk">
          <DashboardRiskWidget />
        </div>
        <div className="dashboard-bento-cell dashboard-bento-cell-scans">
          <DashboardScansSummary />
        </div>
        <div className="dashboard-bento-cell dashboard-bento-cell-lists">
          <DashboardTopLists />
        </div>
        <div className="dashboard-bento-cell dashboard-bento-cell-activity">
          <DashboardActivityFeed />
        </div>
      </div>
    </section>
  );
}
