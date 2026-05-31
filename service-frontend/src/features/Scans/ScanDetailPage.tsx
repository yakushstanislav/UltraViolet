import {
  AlertTriangle,
  ArrowLeft,
  ArrowLeftRight,
  Ban,
  CheckCircle2,
  Minus,
  Pause,
  PauseCircle,
  Play,
  Plus,
  RotateCcw,
  StopCircle,
  XCircle,
} from 'lucide-react';
import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { toast } from 'sonner';

import { ConfirmDialog } from '@components/ConfirmDialog';
import { UvCardList } from '@components/UvCardList';
import { PaginationBarDock } from '@components/PaginationBarDock';
import { HostHoverCard } from '@components/HostHoverCard';
import { InlineError } from '@components/InlineError';
import { RealtimePanelBadge } from '@components/RealtimePanelBadge';
import { Select } from '@components/Select';
import { resolveScanConflictErrorMessage } from '@helpers/scanConflictApiError';
import { showActionError } from '@helpers/uiError';
import {
  formatDate,
  formatPortsExpr,
  formatScanMode,
  statusClass,
} from '@helpers/format';
import { hostPathFromScanTarget } from '@helpers/hostPathFromScanTarget';
import { scrollPaginationAnchor } from '@helpers/scrollPaginationAnchor';
import { parsePositiveInt } from '@helpers/searchParams';
import {
  cancelScan,
  getScan,
  getScanDelta,
  getScanDeltaEvents,
  pauseScan,
  restartScan,
  resumeScan,
} from '@services/ScanAPI';
import { useAppSelector } from '@store/store';
import type {
  RecentScannedHost,
  Scan,
  ScanDeltaEvent,
  ScanDeltaSummary,
} from '@/types/scans';
import { CountryTargetBadge } from './CountryTargetBadge';
import { RandomTargetBadge } from './RandomTargetBadge';
import { useIsMobile, useIsPhablet } from '@/hooks/useBreakpoint';
import { useRealtimeConnection } from '@hooks/useRealtimeConnection';
import { useRealtimeScan } from '@hooks/useRealtimeEvents';
import {
  buildStatChips,
  formatStats,
  toNonNegativeCount,
} from './scanStatsHelpers';
import { RecentScannedHosts } from './RecentScannedHosts';
import { ScanDetailActionsMenu } from './ScanDetailActionsMenu';
import { ScanProgressBar } from './ScanProgressBar';

const DEFAULT_DELTA_EVENTS_LIMIT = 25;
const DELTA_EVENTS_LIMIT_OPTIONS = [25, 50, 100] as const;

function parseScanId(raw: string | undefined): number | null {
  if (!raw) {
    return null;
  }

  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) {
    return null;
  }

  return n;
}

function snapshotHostsFromEvent(data: unknown): { host_id: number; ip: string }[] {
  if (!data || typeof data !== 'object') {
    return [];
  }

  const d = data as Record<string, unknown>;
  const rh = d.recent_hosts;

  if (Array.isArray(rh)) {
    const out: { host_id: number; ip: string }[] = [];

    for (const item of rh) {
      if (!item || typeof item !== 'object') {
        continue;
      }

      const h = item as Record<string, unknown>;
      const hostIdRaw = h.host_id;
      const host_id =
        typeof hostIdRaw === 'number' ? hostIdRaw : Number(hostIdRaw);
      const ip = typeof h.ip === 'string' ? h.ip : '';

      if (Number.isFinite(host_id) && host_id > 0 && ip !== '') {
        out.push({ host_id, ip });
      }
    }

    return out;
  }

  const hostIdRaw = d.host_id;
  const host_id =
    typeof hostIdRaw === 'number' ? hostIdRaw : Number(hostIdRaw);
  const ip = typeof d.ip === 'string' ? d.ip : '';

  if (Number.isFinite(host_id) && host_id > 0 && ip !== '') {
    return [{ host_id, ip }];
  }

  return [];
}

function mergeRecentHostsWs(
  prev: RecentScannedHost[] | undefined,
  incoming: { host_id: number; ip: string }[],
  scannedAt: string,
  limit = 10,
): RecentScannedHost[] {
  const next: RecentScannedHost[] = [];
  const seen = new Set<number>();

  const push = (row: RecentScannedHost): void => {
    if (seen.has(row.host_id)) {
      return;
    }

    seen.add(row.host_id);
    next.push(row);
  };

  for (const h of incoming) {
    push({
      host_id: h.host_id,
      ip: h.ip,
      scanned_at: scannedAt,
    });

    if (next.length >= limit) {
      return next;
    }
  }

  for (const h of prev ?? []) {
    push(h);

    if (next.length >= limit) {
      break;
    }
  }

  return next;
}

function scanStatusLooksActive(status: Scan['status']): boolean {
  return (
    status === 'RUNNING' ||
    status === 'PENDING' ||
    status === 'PAUSED'
  );
}

function reconcileScanRecentHosts(prev: Scan | null, incoming: Scan): Scan {
  const apiRecent = incoming.recent_hosts;

  if (apiRecent !== undefined && apiRecent.length > 0) {
    return incoming;
  }

  const hsIncoming =
    typeof incoming.hosts_scanned === 'number'
      ? incoming.hosts_scanned
      : toNonNegativeCount(incoming.stats?.hosts_scanned);

  const prevRecent =
    prev !== null && prev.id === incoming.id ? prev.recent_hosts : undefined;

  if (
    scanStatusLooksActive(incoming.status) &&
    hsIncoming > 0 &&
    prevRecent !== undefined &&
    prevRecent.length > 0
  ) {
    return { ...incoming, recent_hosts: prevRecent };
  }

  return incoming;
}

function deltaBadgeLabel(
  changeType: string,
  translate: (key: string) => string
): string {
  switch (changeType) {
    case 'new':
      return translate('scanDetail.deltaEventNew');

    case 'disappeared':
      return translate('scanDetail.deltaEventDisappeared');

    case 'changed':
      return translate('scanDetail.deltaEventChanged');

    default:
      return changeType;
  }
}

export function ScanDetailPage() {
  const { t } = useTranslation();
  const { scanId: scanIdParam } = useParams();
  const navigate = useNavigate();
  const scanId = parseScanId(scanIdParam);
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [stopConfirmOpen, setStopConfirmOpen] = useState(false);
  const [restartConfirmOpen, setRestartConfirmOpen] = useState(false);
  const [delta, setDelta] = useState<ScanDeltaSummary | null>(null);
  const [deltaLoading, setDeltaLoading] = useState(false);
  const [deltaEvents, setDeltaEvents] = useState<ScanDeltaEvent[]>([]);
  const [deltaEventsPage, setDeltaEventsPage] = useState(1);
  const [deltaEventsLimit, setDeltaEventsLimit] = useState(
    DEFAULT_DELTA_EVENTS_LIMIT
  );
  const [deltaEventsTotal, setDeltaEventsTotal] = useState(0);
  const [deltaEventsLoading, setDeltaEventsLoading] = useState(false);
  const role = useAppSelector((state) => state.auth.role);
  const canStop = role === 'operator' || role === 'admin';
  const isMobile = useIsMobile();
  const isPhablet = useIsPhablet();
  const canPause = canStop;
  const scanIsActive =
    scan?.status === 'RUNNING' ||
    scan?.status === 'PENDING' ||
    scan?.status === 'PAUSED';

  const loadControllerRef = useRef<AbortController | null>(null);
  const loadDebounceRef = useRef<number | null>(null);

  const load = useCallback(
    async (options?: { silent?: boolean }) => {
      if (scanId === null) {
        setError(t('scanDetail.invalidScanId'));
        setLoading(false);
        setScan(null);

        return;
      }

      loadControllerRef.current?.abort();
      const controller = new AbortController();
      loadControllerRef.current = controller;

      if (!options?.silent) {
        setLoading(true);
      }

      setError(null);

      try {
        const data = await getScan(scanId, controller.signal);

        if (controller.signal.aborted) {
          return;
        }

        setScan((prev) => reconcileScanRecentHosts(prev, data));
      } catch {
        if (controller.signal.aborted) {
          return;
        }

        setError(t('scanDetail.scanNotFound'));
        setScan(null);
      } finally {
        if (!controller.signal.aborted && !options?.silent) {
          setLoading(false);
        }
      }
    },
    [scanId, t],
  );

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    return () => {
      loadControllerRef.current?.abort();
    };
  }, []);

  const scanIsDone = scan?.status === 'DONE';

  const deltaEventsPages = useMemo(
    () => Math.max(1, Math.ceil(deltaEventsTotal / deltaEventsLimit)),
    [deltaEventsLimit, deltaEventsTotal]
  );

  useEffect(() => {
    if (loadDebounceRef.current !== null) {
      window.clearTimeout(loadDebounceRef.current);
      loadDebounceRef.current = null;
    }

    setDeltaEventsPage(1);
    setDeltaEventsLimit(DEFAULT_DELTA_EVENTS_LIMIT);
    setDeltaEvents([]);
    setDeltaEventsTotal(0);
  }, [scanId]);

  useEffect(() => {
    if (!scanIsDone || scanId === null) {
      setDelta(null);
      setDeltaEvents([]);
      setDeltaEventsTotal(0);

      return;
    }

    const controller = new AbortController();

    setDeltaLoading(true);

    getScanDelta(scanId, controller.signal)
      .then((data) => {
        if (controller.signal.aborted) {
          return;
        }

        setDelta(data);
      })
      .catch(() => {
        if (controller.signal.aborted) {
          return;
        }

        setDelta(null);
      })
      .finally(() => {
        if (controller.signal.aborted) {
          return;
        }

        setDeltaLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [scanIsDone, scanId]);

  useEffect(() => {
    if (!scanIsDone || scanId === null) {
      return;
    }

    const controller = new AbortController();

    setDeltaEventsLoading(true);

    getScanDeltaEvents(scanId, deltaEventsPage, deltaEventsLimit, controller.signal)
      .then((data) => {
        if (controller.signal.aborted) {
          return;
        }

        setDeltaEvents(data.items ?? []);
        setDeltaEventsTotal(data.total ?? 0);
      })
      .catch(() => {
        if (controller.signal.aborted) {
          return;
        }

        setDeltaEvents([]);
        setDeltaEventsTotal(0);
      })
      .finally(() => {
        if (controller.signal.aborted) {
          return;
        }

        setDeltaEventsLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [deltaEventsLimit, deltaEventsPage, scanId, scanIsDone]);

  const handleStop = () => {
    if (!scan) {
      return;
    }

    if (!canStop) {
      showActionError(null, 'scanDetail.toastStopInsufficient');
      return;
    }

    setStopConfirmOpen(true);
  };

  const doStop = async () => {
    if (!scan) {
      return;
    }

    const previousScan = scan;

    try {
      setStopping(true);
      const result = await cancelScan(scan.id);
      setScan((prev) =>
        prev
          ? {
              ...prev,
              status: result.status,
              cancel_requested:
                result.status === 'RUNNING' ? true : prev.cancel_requested,
            }
          : prev
      );
      toast.success(t('toasts.scanStopRequested', { id: scan.id }));
      void load();
    } catch (err) {
      setScan(previousScan);
      toast.error(resolveScanConflictErrorMessage(err, t('toasts.scanStopFailed')));
      void load();
    } finally {
      setStopping(false);
    }
  };

  const handlePause = async () => {
    if (!scan) {
      return;
    }

    if (!canPause) {
      showActionError(null, 'scanDetail.toastPauseInsufficient');
      return;
    }

    try {
      setPausing(true);
      const result = await pauseScan(scan.id);
      setScan((prev) =>
        prev
          ? {
              ...prev,
              status: result.status,
              pause_requested:
                result.status === 'RUNNING' ? true : prev.pause_requested,
            }
          : prev
      );
      toast.success(t('toasts.scanPauseRequestedDetail', { id: scan.id }));
      void load();
    } catch (err) {
      toast.error(resolveScanConflictErrorMessage(err, t('toasts.scanPauseFailed')));
    } finally {
      setPausing(false);
    }
  };

  const handleResume = async () => {
    if (!scan) {
      return;
    }

    if (!canPause) {
      showActionError(null, 'scanDetail.toastResumeInsufficient');
      return;
    }

    try {
      setResuming(true);
      const result = await resumeScan(scan.id);
      setScan((prev) =>
        prev
          ? {
              ...prev,
              status: result.status,
              pause_requested: false,
            }
          : prev
      );
      toast.success(
        result.status === 'PAUSED'
          ? t('scansPage.toastResumePaused', { id: scan.id })
          : t('scansPage.toastResumeCanceled', { id: scan.id })
      );
      void load();
    } catch (err) {
      toast.error(resolveScanConflictErrorMessage(err, t('toasts.scanResumeFailed')));
    } finally {
      setResuming(false);
    }
  };

  const handleRestart = () => {
    if (!scan) {
      return;
    }

    if (!canPause) {
      showActionError(null, 'scanDetail.toastRestartInsufficient');
      return;
    }

    setRestartConfirmOpen(true);
  };

  const doRestart = async () => {
    if (!scan) {
      return;
    }

    try {
      setRestarting(true);
      const result = await restartScan(scan.id);

      toast.success(
        t('toasts.scanRestartQueued', { id: result.id, status: result.status })
      );
      void load();
    } catch (err) {
      toast.error(resolveScanConflictErrorMessage(err, t('toasts.scanRestartFailed')));
    } finally {
      setRestarting(false);
    }
  };

  const connectionState = useRealtimeConnection();

  const scheduleLoad = useCallback(() => {
    if (loadDebounceRef.current !== null) {
      window.clearTimeout(loadDebounceRef.current);
    }

    loadDebounceRef.current = window.setTimeout(() => {
      loadDebounceRef.current = null;
      void load({ silent: true });
    }, 300);
  }, [load]);

  useRealtimeScan(scanId, (event) => {
    if (event.type === 'scan.snapshot' && scanId !== null) {
      const hosts = snapshotHostsFromEvent(event.data);

      if (hosts.length > 0) {
        const scannedAt =
          typeof event.ts === 'string' ? event.ts : new Date().toISOString();

        setScan((prev) => {
          if (!prev || prev.id !== scanId) {
            return prev;
          }

          const merged = mergeRecentHostsWs(prev.recent_hosts, hosts, scannedAt);

          return { ...prev, recent_hosts: merged };
        });
      }
    }

    if (
      event.type === 'scan.status' ||
      event.type === 'scan.stats' ||
      event.type === 'scan.snapshot'
    ) {
      scheduleLoad();
    }
  });

  useEffect(() => {
    if (!scanIsActive || connectionState === 'connected') {
      return;
    }

    const interval = window.setInterval(() => {
      void load({ silent: true });
    }, 4000);

    return () => {
      window.clearInterval(interval);
    };
  }, [connectionState, load, scanIsActive]);

  useEffect(() => {
    return () => {
      if (loadDebounceRef.current !== null) {
        window.clearTimeout(loadDebounceRef.current);
      }
    };
  }, []);

  if (scanId === null) {
    return (
      <section className="page scans-detail-page">
        <div className="scans-detail-toolbar">
          <p className="muted-text">{t('scanDetail.invalidScanId')}</p>
          <Link className="secondary scans-detail-back" to="/scans">
            <ArrowLeft size={16} />
            {t('scanDetail.back')}
          </Link>
        </div>
      </section>
    );
  }

  if (loading && !scan) {
    return (
      <section className="page scans-detail-page">
        <div className="scans-detail-toolbar">
          <p className="muted-text">{t('scanDetail.loadingScan')}</p>
        </div>
      </section>
    );
  }

  if (error && !scan) {
    return (
      <section className="page scans-detail-page">
        <div className="scans-detail-toolbar">
          <InlineError message={error} onRetry={() => void load()} />
          <Link className="secondary scans-detail-back" to="/scans">
            <ArrowLeft size={16} />
            {t('scanDetail.back')}
          </Link>
        </div>
      </section>
    );
  }

  if (!scan) {
    return null;
  }

  const statChips = buildStatChips(scan.stats);
  const errCount = toNonNegativeCount(scan.stats?.errors);
  const doneWithErrors = scan.status === 'DONE' && errCount > 0;
  const scanHostPath = scan.cidr ? hostPathFromScanTarget(scan.cidr) : null;

  return (
    <section className="page scans-detail-page">
      <div className="scans-detail-toolbar">
        <div className="scans-detail-header scans-detail-header--actions">
        <button
          className="secondary scans-detail-back-btn"
          onClick={() => navigate(-1)}
          type="button"
        >
          <ArrowLeft size={16} />
          {t('scanDetail.backButton')}
        </button>
        {isPhablet ? (
          <ScanDetailActionsMenu
            canPause={canPause}
            canStop={canStop}
            onPause={() => void handlePause()}
            onRestart={() => void handleRestart()}
            onResume={() => void handleResume()}
            onStop={() => void handleStop()}
            pausing={pausing}
            restarting={restarting}
            resuming={resuming}
            scan={scan}
            stopping={stopping}
          />
        ) : (
          <>
            {canPause && scan.status === 'RUNNING' && !scan.pause_requested && (
              <button
                className="secondary scans-pause-btn"
                disabled={pausing}
                onClick={() => void handlePause()}
                type="button"
              >
                <Pause size={16} />
                {t('scanDetail.pauseScan')}
              </button>
            )}
            {canPause &&
              (scan.status === 'PAUSED' ||
                (scan.status === 'RUNNING' && scan.pause_requested)) && (
                <button
                  className="secondary scans-resume-btn"
                  disabled={resuming}
                  onClick={() => void handleResume()}
                  type="button"
                >
                  <Play size={16} />
                  {scan.status === 'RUNNING' && scan.pause_requested
                    ? t('scanDetail.cancelPause')
                    : t('scanDetail.resumeScan')}
                </button>
              )}
            {canPause &&
              (scan.status === 'DONE' ||
                scan.status === 'FAILED' ||
                scan.status === 'CANCELED' ||
                scan.status === 'PAUSED') && (
                <button
                  className="secondary scans-restart-btn"
                  disabled={restarting}
                  onClick={() => void handleRestart()}
                  type="button"
                >
                  <RotateCcw size={16} />
                  {t('scanDetail.restartScan')}
                </button>
              )}
            {canStop &&
              (scan.status === 'PENDING' ||
                scan.status === 'RUNNING' ||
                scan.status === 'PAUSED') && (
                <button
                  className="secondary scans-stop-btn"
                  disabled={stopping || scan.cancel_requested === true}
                  onClick={() => void handleStop()}
                  type="button"
                >
                  <StopCircle size={16} />
                  {scan.cancel_requested
                    ? t('scanDetail.stopping')
                    : t('scanDetail.stopScan')}
                </button>
              )}
          </>
        )}
        </div>
      </div>
      <div className="scans-detail-body">
      <div className="panel scans-detail-title-panel">
        <div className="scans-detail-title-row">
          <h1 className="scans-detail-title">
            <span className="cell-mono">#{scan.id}</span>{' '}
            <span>{scan.name || t('scanDetail.defaultScanName')}</span>
          </h1>
          <div className="scans-detail-status-wrap">
            <span className={statusClass(scan.status)} title={scan.status}>
              {scan.status === 'FAILED' && (
                <XCircle aria-hidden className="scans-status-icon" size={16} />
              )}
              {scan.status === 'DONE' && !doneWithErrors && (
                <CheckCircle2
                  aria-hidden
                  className="scans-status-icon"
                  size={16}
                />
              )}
              {scan.status === 'DONE' && doneWithErrors && (
                <AlertTriangle
                  aria-hidden
                  className="scans-status-icon scans-status-icon-warn"
                  size={16}
                />
              )}
              {scan.status === 'CANCELED' && (
                <Ban aria-hidden className="scans-status-icon" size={16} />
              )}
              {scan.status === 'PAUSED' && (
                <PauseCircle
                  aria-hidden
                  className="scans-status-icon"
                  size={16}
                />
              )}
              {scan.status}
            </span>
            {doneWithErrors && (
              <span className="status-warn-badge">
                {t('scanDetail.completedWithErrors')}
              </span>
            )}
            {scanIsActive && <RealtimePanelBadge />}
          </div>
        </div>
        <p className="scans-detail-subtitle cell-mono">
          {scan.target_strategy === 'random' ? (
            <RandomTargetBadge hostLimit={scan.host_limit} size="md" />
          ) : scan.target_strategy === 'country' ? (
            <CountryTargetBadge
              country={scan.country ?? ''}
              hostLimit={scan.host_limit}
              size="md"
            />
          ) : scanHostPath ? (
            <Link to={scanHostPath}>{scan.cidr}</Link>
          ) : (
            scan.cidr
          )}
        </p>
      </div>

      <div className="panel scans-detail-grid">
        <div>
          <h2 className="scans-detail-section-title">
            {t('scanDetail.timing')}
          </h2>
          <dl className="scans-detail-dl">
            <div>
              <dt>{t('scanDetail.created')}</dt>
              <dd className="cell-mono">{formatDate(scan.created_at)}</dd>
            </div>
            <div>
              <dt>{t('scanDetail.started')}</dt>
              <dd className="cell-mono">
                {scan.started_at
                  ? formatDate(scan.started_at)
                  : t('common.dash')}
              </dd>
            </div>
            <div>
              <dt>{t('scanDetail.finished')}</dt>
              <dd className="cell-mono">
                {scan.finished_at
                  ? formatDate(scan.finished_at)
                  : t('common.dash')}
              </dd>
            </div>
            {scan.stats_updated_at && (
              <div>
                <dt>{t('scanDetail.statsUpdated')}</dt>
                <dd className="cell-mono">
                  {formatDate(scan.stats_updated_at)}
                </dd>
              </div>
            )}
          </dl>
        </div>
        <div>
          <h2 className="scans-detail-section-title">
            {t('scanDetail.ports')}
          </h2>
          <dl className="scans-detail-dl">
            <div>
              <dt>{t('scanDetail.discovery')}</dt>
              <dd>
                {formatScanMode(
                  scan.mode,
                  scan.target_strategy,
                  scan.slow_profile
                )}
              </dd>
            </div>
          </dl>
          <p className="cell-mono scans-detail-ports">
            {formatPortsExpr(scan.ports_expr)}
          </p>
        </div>
      </div>

      <div className="panel scans-detail-stats-panel">
        <ScanProgressBar scan={scan} />
        <hr className="scans-detail-stats-divider" />
        <h2 className="scans-detail-section-title">{t('scanDetail.stats')}</h2>
        <div
          className="stats-chips scans-detail-stats-chips"
          title={formatStats(scan.stats)}
        >
          {statChips.map((chip) => (
            <span
              className={`stats-chip stats-chip-tone-${chip.tone}`}
              key={chip.rawKey}
            >
              <span className="stats-chip-label">{chip.label}</span>
              <span className="stats-chip-value">{chip.valueText}</span>
            </span>
          ))}
          {statChips.length === 0 && scanIsActive && (
            <div className="scan-stats-waiting">
              <span aria-hidden className="scan-stats-waiting-dots">
                <span />
                <span />
                <span />
              </span>
              <span>{t('scanDetail.statsScanning')}</span>
            </div>
          )}
          {statChips.length === 0 && !scanIsActive && (
            <span className="muted-text">{t('scanDetail.noStatsYet')}</span>
          )}
        </div>
      </div>

      {(scanIsActive &&
        toNonNegativeCount(scan.hosts_scanned ?? scan.stats?.hosts_scanned) >
          0) ||
      (scan.recent_hosts !== undefined && scan.recent_hosts.length > 0) ? (
        <RecentScannedHosts
          hosts={scan.recent_hosts ?? []}
          live={scanIsActive}
        />
      ) : null}

      {scan.status === 'DONE' && (deltaLoading || delta) && (
        <div className="panel scans-detail-delta-panel pagination-bar-scope">
          <div className="scans-detail-delta-header">
            <h2 className="scans-detail-section-title">
              {t('scanDetail.changes')}
            </h2>
            {!deltaLoading && delta && delta.previous_scan_id != null && (
              <Link
                className="secondary scans-detail-delta-prev-link"
                to={`/scans/${delta.previous_scan_id}`}
              >
                {t('scanDetail.previousScan', { id: delta.previous_scan_id })}
              </Link>
            )}
          </div>

          {deltaLoading && (
            <div className="scans-detail-delta-grid">
              {(['new', 'disappeared', 'changed'] as const).map((k) => (
                <div
                  className="scans-detail-delta-card scans-detail-delta-card-skeleton"
                  key={k}
                />
              ))}
            </div>
          )}

          {!deltaLoading && delta && (
            <div className="scans-detail-delta-grid">
              <div className="scans-detail-delta-card scans-detail-delta-card-new">
                <span className="scans-detail-delta-card-value">
                  {delta.new_services > 0
                    ? `+${delta.new_services}`
                    : delta.new_services}
                </span>
                <span className="scans-detail-delta-card-label">
                  {t('scanDetail.deltaNew')}
                </span>
              </div>
              <div className="scans-detail-delta-card scans-detail-delta-card-disappeared">
                <span className="scans-detail-delta-card-value">
                  {delta.disappeared_services > 0
                    ? `−${delta.disappeared_services}`
                    : delta.disappeared_services}
                </span>
                <span className="scans-detail-delta-card-label">
                  {t('scanDetail.deltaDisappeared')}
                </span>
              </div>
              <div className="scans-detail-delta-card scans-detail-delta-card-changed">
                <span className="scans-detail-delta-card-value">
                  {delta.changed_services}
                </span>
                <span className="scans-detail-delta-card-label">
                  {t('scanDetail.deltaChanged')}
                </span>
              </div>
            </div>
          )}
          {!deltaLoading && deltaEventsTotal > 0 && (
            <Fragment>
            {isMobile ? (
              <UvCardList
                className="scans-detail-delta-card-list"
                getRowId={(event) => event.id}
                loading={deltaEventsLoading}
                renderCard={(event) => {
                  const details = event.Details ?? {};
                  const port = details.port;
                  const protocol = details.protocol;
                  const ip = details.ip;
                  const bannerHash =
                    typeof details.banner_hash === 'string'
                      ? details.banner_hash
                      : null;
                  const detailsJson = JSON.stringify(details, null, 2);
                  const portLabel =
                    typeof port === 'number'
                      ? String(port)
                      : typeof port === 'string' && port !== ''
                        ? port
                        : t('common.dash');

                  return (
                    <>
                      <div className="uv-card__head">
                        <span
                          className={`delta-event-badge delta-event-badge-${event.ChangeType}`}
                        >
                          {event.ChangeType === 'new' && (
                            <Plus aria-hidden size={12} />
                          )}
                          {event.ChangeType === 'disappeared' && (
                            <Minus aria-hidden size={12} />
                          )}
                          {event.ChangeType === 'changed' && (
                            <ArrowLeftRight aria-hidden size={12} />
                          )}
                          {deltaBadgeLabel(event.ChangeType, t)}
                        </span>
                        <span className="cell-mono">{portLabel}</span>
                      </div>
                      <div className="uv-card__meta">
                        {typeof protocol === 'string' && protocol !== '' ? (
                          <span className="delta-event-proto">{protocol}</span>
                        ) : (
                          <span className="muted-text">{t('common.dash')}</span>
                        )}
                        {typeof ip === 'string' ? (
                          <HostHoverCard ip={ip}>
                            <Link to={`/hosts/${encodeURIComponent(ip)}`}>
                              {ip}
                            </Link>
                          </HostHoverCard>
                        ) : (
                          <span className="muted-text">{t('common.dash')}</span>
                        )}
                      </div>
                      {bannerHash ? (
                        <code
                          className="cell-mono delta-event-hash uv-card__payload"
                          title={detailsJson}
                        >
                          {bannerHash.slice(0, 12)}
                          {bannerHash.length > 12 ? '…' : ''}
                        </code>
                      ) : (
                        <span className="muted-text" title={detailsJson}>
                          {t('common.dash')}
                        </span>
                      )}
                    </>
                  );
                }}
                rows={deltaEvents}
              />
            ) : (
            <div className="table-wrap scans-detail-delta-events pagination-scroll-anchor">
              <table
                className={`scans-detail-delta-events-table${deltaEventsLoading ? ' scans-detail-delta-events-table-loading' : ''}`}
              >
                <thead>
                  <tr>
                    <th className="scans-detail-delta-col-type">
                      {t('columns.type')}
                    </th>
                    <th className="scans-detail-delta-col-port">
                      {t('columns.port')}
                    </th>
                    <th className="scans-detail-delta-col-protocol">
                      {t('columns.protocol')}
                    </th>
                    <th className="scans-detail-delta-col-ip">
                      {t('columns.ip')}
                    </th>
                    <th className="scans-detail-delta-col-banner">
                      {t('columns.bannerHash')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {deltaEvents.map((event) => {
                    const details = event.Details ?? {};
                    const port = details.port;
                    const protocol = details.protocol;
                    const ip = details.ip;
                    const bannerHash =
                      typeof details.banner_hash === 'string'
                        ? details.banner_hash
                        : null;
                    const detailsJson = JSON.stringify(details, null, 2);

                    return (
                      <tr key={event.id}>
                        <td className="scans-detail-delta-col-type">
                          <span
                            className={`delta-event-badge delta-event-badge-${event.ChangeType}`}
                          >
                            {event.ChangeType === 'new' && (
                              <Plus aria-hidden size={12} />
                            )}
                            {event.ChangeType === 'disappeared' && (
                              <Minus aria-hidden size={12} />
                            )}
                            {event.ChangeType === 'changed' && (
                              <ArrowLeftRight aria-hidden size={12} />
                            )}
                            {deltaBadgeLabel(event.ChangeType, t)}
                          </span>
                        </td>
                        <td className="cell-mono scans-detail-delta-col-port">
                          {typeof port === 'number'
                            ? port
                            : typeof port === 'string' && port !== ''
                              ? port
                              : t('common.dash')}
                        </td>
                        <td className="scans-detail-delta-col-protocol">
                          {typeof protocol === 'string' && protocol !== '' ? (
                            <span className="delta-event-proto">
                              {protocol}
                            </span>
                          ) : (
                            <span className="muted-text">
                              {t('common.dash')}
                            </span>
                          )}
                        </td>
                        <td className="cell-mono scans-detail-delta-col-ip">
                          {typeof ip === 'string' ? (
                            <HostHoverCard ip={ip}>
                              <Link to={`/hosts/${encodeURIComponent(ip)}`}>
                                {ip}
                              </Link>
                            </HostHoverCard>
                          ) : (
                            <span className="muted-text">
                              {t('common.dash')}
                            </span>
                          )}
                        </td>
                        <td className="scans-detail-delta-col-banner">
                          {bannerHash ? (
                            <code
                              className="cell-mono delta-event-hash"
                              title={detailsJson}
                            >
                              {bannerHash.slice(0, 12)}
                              {bannerHash.length > 12 ? '…' : ''}
                            </code>
                          ) : (
                            <span className="muted-text" title={detailsJson}>
                              {t('common.dash')}
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            )}
            <PaginationBarDock>
            <div className="panel pagination-bar scans-detail-delta-pagination">
              <span className="pagination-bar-meta">
                {t('scansPage.pagination', {
                  page: deltaEventsPage,
                  pages: deltaEventsPages,
                  total: deltaEventsTotal,
                })}
              </span>
              <div className="header-actions pagination-bar-controls">
                <label className="muted-text pagination-bar-limit">
                  {t('scansPage.limitLabel')}
                  <Select
                    compact
                    disabled={deltaEventsLoading}
                    onChange={(next) => {
                      const nextLimit = parsePositiveInt(
                        next,
                        DEFAULT_DELTA_EVENTS_LIMIT
                      );
                      setDeltaEventsLimit(nextLimit);
                      setDeltaEventsPage(1);
                    }}
                    options={DELTA_EVENTS_LIMIT_OPTIONS.map((value) => ({
                      label: String(value),
                      value: String(value),
                    }))}
                    value={String(deltaEventsLimit)}
                  />
                </label>
                <div className="pagination-bar-nav">
                  <button
                    className="secondary"
                    disabled={deltaEventsPage <= 1 || deltaEventsLoading}
                    onClick={() => {
                      setDeltaEventsPage((prev) => Math.max(1, prev - 1));
                    }}
                    type="button"
                  >
                    {t('common.prev')}
                  </button>
                  <button
                    className="secondary"
                    disabled={
                      deltaEventsPage >= deltaEventsPages || deltaEventsLoading
                    }
                    onClick={() => {
                      setDeltaEventsPage((prev) =>
                        Math.min(deltaEventsPages, prev + 1)
                      );
                      requestAnimationFrame(() => scrollPaginationAnchor());
                    }}
                    type="button"
                  >
                    {t('common.next')}
                  </button>
                </div>
              </div>
            </div>
            </PaginationBarDock>
            </Fragment>
          )}
        </div>
      )}

      <ConfirmDialog
        cancelLabel={t('scanDetail.stopConfirmKeep')}
        confirmIcon={<StopCircle size={16} />}
        confirmLabel={t('scanDetail.stopScan')}
        description={t('scanDetail.stopConfirmDescription')}
        icon={<StopCircle size={20} />}
        onConfirm={doStop}
        onOpenChange={setStopConfirmOpen}
        open={stopConfirmOpen}
        title={t('scanDetail.stopConfirmTitle', { id: scan.id })}
        tone="danger"
      >
        <div className="confirm-dialog-meta">
          <span className="confirm-dialog-meta-id">#{scan.id}</span>
          <span className="confirm-dialog-meta-name">
            {scan.name || t('scanDetail.defaultScanName')}
          </span>
        </div>
        <ul className="confirm-dialog-list">
          <li>{t('scanDetail.stopConfirmList1')}</li>
          <li>{t('scanDetail.stopConfirmList2')}</li>
          <li>{t('scanDetail.stopConfirmList3')}</li>
        </ul>
      </ConfirmDialog>

      <ConfirmDialog
        confirmIcon={<RotateCcw size={16} />}
        confirmLabel={t('scanDetail.restartScan')}
        description={t('scanDetail.restartConfirmDescription')}
        icon={<RotateCcw size={20} />}
        onConfirm={doRestart}
        onOpenChange={setRestartConfirmOpen}
        open={restartConfirmOpen}
        title={t('scanDetail.restartConfirmTitle', { id: scan.id })}
        tone="warning"
      >
        <div className="confirm-dialog-meta">
          <span className="confirm-dialog-meta-id">#{scan.id}</span>
          <span className="confirm-dialog-meta-name">
            {scan.name || t('scanDetail.defaultScanName')}
          </span>
        </div>
        <ul className="confirm-dialog-list">
          <li>{t('scanDetail.restartConfirmList1')}</li>
          <li>{t('scanDetail.restartConfirmList2')}</li>
          <li>{t('scanDetail.restartConfirmList3')}</li>
        </ul>
      </ConfirmDialog>
      </div>
    </section>
  );
}
