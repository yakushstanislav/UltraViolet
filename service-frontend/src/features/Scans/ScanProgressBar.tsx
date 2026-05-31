import { CheckCircle2, Gauge, Loader2, Radio, Timer } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { Scan, ScanStatus } from '@/types/scans';

type ScanProgressBarProps = {
  scan: Scan;
};

const RATE_MIN_ELAPSED_MS = 5000;
const RATE_MIN_HOSTS_PER_SEC = 0.05;

function progressDenominator(scan: Scan): number | null {
  if (scan.target_strategy === 'random' && scan.host_limit) {
    return scan.host_limit;
  }

  if (!scan.cidr) {
    return null;
  }

  const parts = scan.cidr.split('/');
  if (parts.length !== 2) {
    return null;
  }

  const [head, mask] = parts;
  if (head === undefined || mask === undefined) {
    return null;
  }

  const bits = Number(mask);
  const isV4 = head.includes('.');
  const totalBits = isV4 ? 32 : 128;

  if (!Number.isFinite(bits) || bits < 0 || bits > totalBits) {
    return null;
  }

  const hostBits = totalBits - bits;
  if (hostBits >= 31) {
    return null;
  }

  let count = 2 ** hostBits;
  if (isV4 && bits <= 30) {
    count = Math.max(0, count - 2);
  }

  return count;
}

function isActiveScan(status: ScanStatus): boolean {
  return status === 'RUNNING' || status === 'PENDING' || status === 'PAUSED';
}

// Only the slow engine emits per-IP target progress. masscan/zmap scan the
// whole CIDR as one subprocess call, so we have no smooth signal to drive
// the bar — backend returns progress=null and we suppress the bar entirely.
function hasProgressSignal(scan: Scan): boolean {
  const mode = scan.mode ?? 'slow';

  return mode === 'slow';
}

function emittedTargetsFromStats(scan: Scan): number {
  const raw = scan.stats?.emitted_targets;
  if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) {
    return raw;
  }

  return 0;
}

function formatDurationSec(totalSeconds: number): string {
  const seconds = Math.max(0, Math.round(totalSeconds));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;

  if (h > 0) {
    return `${h}h ${m}m`;
  }

  if (m > 0) {
    return `${m}m ${s}s`;
  }

  return `${s}s`;
}

function formatRate(hostsPerSec: number): string {
  if (hostsPerSec >= 100) {
    return hostsPerSec.toFixed(0);
  }

  if (hostsPerSec >= 10) {
    return hostsPerSec.toFixed(1);
  }

  return hostsPerSec.toFixed(2);
}

export function ScanProgressBar({ scan }: ScanProgressBarProps) {
  const { t } = useTranslation();
  const [now, setNow] = useState(() => Date.now());

  const active = isActiveScan(scan.status);
  const isRunning = scan.status === 'RUNNING';

  useEffect(() => {
    if (!isRunning) {
      return;
    }

    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [isRunning]);

  if (scan.status === 'CANCELED' || scan.status === 'FAILED') {
    return null;
  }

  const hostsScanned = scan.hosts_scanned ?? 0;
  const denom = progressDenominator(scan);
  const hasHosts = hostsScanned > 0;
  const hasSignal = hasProgressSignal(scan);

  let percent = 0;
  let indeterminate = false;
  let showBar = true;

  if (!hasSignal) {
    showBar = false;
  } else if (scan.status === 'DONE') {
    percent = 100;
    indeterminate = false;
  } else if (scan.progress != null) {
    percent = Math.min(100, Math.max(0, Math.round(scan.progress * 100)));
    indeterminate = false;
  } else if (active) {
    indeterminate = true;
    percent = 0;
  } else {
    showBar = false;
  }

  const tone =
    scan.status === 'DONE'
      ? 'complete'
      : hasHosts
        ? 'active'
        : active
          ? 'scanning'
          : 'idle';

  let title: string;
  let subtitle: string | null = null;

  if (scan.status === 'DONE') {
    title = t('scanDetail.progressCompleteTitle', {
      count: hostsScanned.toLocaleString(),
    });
    subtitle =
      hostsScanned === 0 ? t('scanDetail.progressCompleteEmpty') : null;
  } else if (hasHosts) {
    title = hostsScanned.toLocaleString();
    subtitle = t('scanDetail.progressLiveHostsLabel');

    if (hasSignal && scan.progress != null && denom != null) {
      subtitle = t('scanDetail.progressOfTotal', {
        scanned: hostsScanned.toLocaleString(),
        total: denom.toLocaleString(),
        percent: Math.min(100, Math.max(0, Math.round(scan.progress * 100))),
      });
    }
  } else if (active) {
    title = t('scanDetail.progressScanningTitle');
    subtitle = t('scanDetail.progressScanningHint');
  } else {
    title = '0';
    subtitle = t('scanDetail.progressLiveHostsLabel');
  }

  let rateText: string | null = null;
  let etaText: string | null = null;

  if (isRunning && hasSignal && scan.started_at) {
    const emitted = emittedTargetsFromStats(scan);
    const startedAt = new Date(scan.started_at).getTime();
    const elapsedMs = now - startedAt;

    if (emitted > 0 && Number.isFinite(elapsedMs) && elapsedMs >= RATE_MIN_ELAPSED_MS) {
      const rate = emitted / (elapsedMs / 1000);

      if (rate >= RATE_MIN_HOSTS_PER_SEC) {
        rateText = t('scanDetail.progressRate', { rate: formatRate(rate) });

        if (denom != null && denom > emitted) {
          const remaining = denom - emitted;
          etaText = t('scanDetail.progressEta', {
            duration: formatDurationSec(remaining / rate),
          });
        }
      }
    }
  }

  return (
    <div className={`scan-live-metric scan-live-metric-${tone}`}>
      <div className="scan-live-metric-body">
        <div
          aria-hidden
          className={`scan-live-metric-icon scan-live-metric-icon-${tone}`}
        >
          {scan.status === 'DONE' ? (
            <CheckCircle2 size={22} strokeWidth={2} />
          ) : active ? (
            <Loader2 className="scan-live-metric-spin" size={22} strokeWidth={2} />
          ) : (
            <Radio size={22} strokeWidth={2} />
          )}
        </div>

        <div className="scan-live-metric-copy">
          <div className="scan-live-metric-value-row">
            <span className="scan-live-metric-value">{title}</span>
            {hasHosts && scan.status !== 'DONE' && (
              <span className="scan-live-metric-badge">
                {t('scanDetail.progressLiveBadge')}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="scan-live-metric-subtitle">{subtitle}</p>
          )}
          {(rateText || etaText) && (
            <p className="scan-live-metric-telemetry">
              {rateText && (
                <span className="scan-live-metric-telemetry-item">
                  <Gauge aria-hidden size={12} />
                  {rateText}
                </span>
              )}
              {etaText && (
                <span className="scan-live-metric-telemetry-item">
                  <Timer aria-hidden size={12} />
                  {etaText}
                </span>
              )}
            </p>
          )}
        </div>
      </div>

      {showBar && (
        <div
          aria-hidden
          className="scan-progress-track"
          role="presentation"
        >
          <div
            className={[
              'scan-progress-fill',
              indeterminate ? 'scan-progress-fill-indeterminate' : '',
            ]
              .filter(Boolean)
              .join(' ')}
            style={indeterminate ? undefined : { width: `${percent}%` }}
          />
        </div>
      )}
    </div>
  );
}
