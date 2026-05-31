import { Globe, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { EmptyState } from '@components/EmptyState';
import { SkeletonRow } from '@components/Skeleton';
import { formatDate } from '@helpers/format';
import type { DnsRecord } from '@/types/hosts';

type HostDnsTableProps = {
  records: DnsRecord[];
  loading?: boolean;
};

const SKELETON_ROWS: Array<Array<'short' | 'mid' | 'long'>> = [
  ['short', 'mid', 'long', 'short', 'short'],
  ['short', 'long', 'mid', 'short', 'short'],
  ['mid', 'short', 'long', 'short', 'short'],
  ['short', 'mid', 'short', 'long', 'short'],
];

export function HostDnsTable({ records, loading = false }: HostDnsTableProps) {
  const { t } = useTranslation();

  return (
    <div className="panel dns-section">
      <h2>{t('hostPage.dns')}</h2>
      {loading && records.length === 0 ? (
        <table className="dns-table">
          <thead>
            <tr>
              <th>{t('columns.type')}</th>
              <th>{t('columns.name')}</th>
              <th>{t('columns.value')}</th>
              <th>{t('columns.source')}</th>
              <th>{t('columns.captured')}</th>
            </tr>
          </thead>
          <tbody>
            {SKELETON_ROWS.map((cells, index) => (
              <SkeletonRow cells={cells} key={index} />
            ))}
          </tbody>
        </table>
      ) : !loading && records.length === 0 ? (
        <EmptyState
          hint={t('emptyState.dns.hint')}
          icon={<Globe size={28} />}
          title={t('emptyState.dns.title')}
        />
      ) : (
        <table className="dns-table">
          <thead>
            <tr>
              <th>{t('columns.type')}</th>
              <th>{t('columns.name')}</th>
              <th>{t('columns.value')}</th>
              <th>{t('columns.source')}</th>
              <th>{t('columns.captured')}</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r, i) => (
              <tr key={i}>
                <td>
                  <span className="dns-type-badge">{r.type}</span>
                </td>
                <td className="cell-mono">{r.name}</td>
                <td className="cell-mono">{r.value}</td>
                <td>
                  <span className="dns-source">
                    {r.source}
                    {r.forward_confirmed && (
                      <ShieldCheck
                        aria-label={t('hostPage.dnsForwardConfirmed')}
                        className="dns-fcrdns-icon"
                        size={14}
                      />
                    )}
                  </span>
                </td>
                <td>
                  <span className="text-muted">{formatDate(r.captured_at)}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
