import { Radio } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { HostHoverCard } from '@components/HostHoverCard';
import { RealtimePanelBadge } from '@components/RealtimePanelBadge';
import { UvCardList } from '@components/UvCardList';
import { formatDate } from '@helpers/format';
import { hostIPFromScanTarget, hostPathFromScanTarget } from '@helpers/hostPathFromScanTarget';
import { useIsMobile } from '@/hooks/useBreakpoint';
import type { RecentScannedHost } from '@/types/scans';

type RecentScannedHostsProps = {
  hosts: RecentScannedHost[];
  live?: boolean;
};

export function RecentScannedHosts({ hosts, live = false }: RecentScannedHostsProps) {
  const { t } = useTranslation();
  const isMobile = useIsMobile();

  const emptyLive = live && hosts.length === 0;

  return (
    <div className="panel scans-detail-recent-panel">
      <div className="scans-detail-recent-header">
        <h2 className="scans-detail-section-title">
          {t('scanDetail.recentHostsTitle')}
          {live ? <RealtimePanelBadge labelKey="realtime.panelStreaming" /> : null}
        </h2>
        {live && (
          <p className="scans-detail-recent-hint">
            <Radio aria-hidden size={13} strokeWidth={2} />
            {t('scanDetail.recentHostsLiveHint')}
          </p>
        )}
      </div>
      <div className="scans-detail-recent-table-wrap">
        {emptyLive ? (
          <p className="muted-text scans-detail-recent-empty">
            {t('scanDetail.recentHostsWaiting')}
          </p>
        ) : isMobile ? (
          <UvCardList
            className="scans-detail-recent-card-list"
            getRowId={(host) => `${host.host_id}-${host.scanned_at}`}
            renderCard={(host) => {
              const isLatest =
                live &&
                hosts[0]?.host_id === host.host_id &&
                hosts[0]?.scanned_at === host.scanned_at;
              const hostIP = hostIPFromScanTarget(host.ip);
              const hostPath = hostPathFromScanTarget(host.ip);

              return (
                <div
                  className={
                    isLatest
                      ? 'uv-card__inner scans-detail-recent-row-latest'
                      : undefined
                  }
                >
                  <div className="uv-card__head">
                    {hostIP !== null && hostPath !== null ? (
                      <HostHoverCard ip={hostIP}>
                        <Link
                          className="scans-detail-recent-ip uv-card__title"
                          to={hostPath}
                        >
                          {hostIP}
                        </Link>
                      </HostHoverCard>
                    ) : (
                      <span className="scans-detail-recent-ip uv-card__title cell-mono">
                        {host.ip}
                      </span>
                    )}
                    <span className="scans-detail-recent-time">
                      {formatDate(host.scanned_at)}
                    </span>
                  </div>
                </div>
              );
            }}
            rows={hosts}
          />
        ) : (
          <table className="scans-detail-recent-table">
            <thead>
              <tr>
                <th>{t('scanDetail.recentHostsIp')}</th>
                <th>{t('scanDetail.recentHostsTime')}</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((host, index) => {
                const hostIP = hostIPFromScanTarget(host.ip);
                const hostPath = hostPathFromScanTarget(host.ip);

                return (
                <tr
                  className={
                    index === 0 && live ? 'scans-detail-recent-row-latest' : undefined
                  }
                  key={`${host.host_id}-${host.scanned_at}`}
                >
                  <td>
                    {hostIP !== null && hostPath !== null ? (
                      <HostHoverCard ip={hostIP}>
                        <Link
                          className="scans-detail-recent-ip"
                          to={hostPath}
                        >
                          {hostIP}
                        </Link>
                      </HostHoverCard>
                    ) : (
                      <span className="scans-detail-recent-ip cell-mono">
                        {host.ip}
                      </span>
                    )}
                  </td>
                  <td className="scans-detail-recent-time">
                    {formatDate(host.scanned_at)}
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
