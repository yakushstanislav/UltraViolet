import { useEffect } from 'react';
import { ChevronLeft, ChevronRight, Network } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { EmptyState } from '@components/EmptyState';
import { SkeletonRow } from '@components/Skeleton';
import type { RelatedHost } from '@/types/hosts';

type RelatedHostsTableProps = {
  items: RelatedHost[];
  loading: boolean;
  page: number;
  limit: number;
  total: number;
  onPageChange: (page: number) => void;
};

const SKELETON_ROWS: Array<Array<'short' | 'mid' | 'long'>> = [
  ['short', 'mid', 'long', 'short'],
  ['short', 'long', 'mid', 'short'],
  ['mid', 'short', 'long', 'short'],
  ['short', 'mid', 'short', 'long'],
];

export function RelatedHostsTable({
  items,
  limit,
  loading,
  onPageChange,
  page,
  total,
}: RelatedHostsTableProps) {
  const { t } = useTranslation();
  const pages = Math.max(1, Math.ceil(total / limit));

  useEffect(() => {
    if (!loading && page > pages) {
      onPageChange(1);
    }
  }, [loading, onPageChange, page, pages]);

  return (
    <div className="panel related-hosts-section">
      <header className="related-hosts-head">
        <span className="related-hosts-head-icon" aria-hidden>
          <Network size={14} />
        </span>
        <h2>{t('hostPage.relatedHosts')}</h2>
        <span className="related-hosts-head-count">{total}</span>
      </header>
      {loading && items.length === 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('columns.ip')}</th>
                <th>{t('columns.sharedVia')}</th>
                <th>{t('columns.value')}</th>
                <th>{t('columns.country')}</th>
              </tr>
            </thead>
            <tbody>
              {SKELETON_ROWS.map((cells, index) => (
                <SkeletonRow cells={cells} key={index} />
              ))}
            </tbody>
          </table>
        </div>
      ) : !loading && items.length === 0 ? (
        <EmptyState
          hint={t('emptyState.relatedHosts.hint')}
          icon={<Network size={28} />}
          title={t('emptyState.relatedHosts.title')}
        />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('columns.ip')}</th>
                <th>{t('columns.sharedVia')}</th>
                <th>{t('columns.value')}</th>
                <th>{t('columns.country')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row, idx) => (
                <tr key={`${row.ip}-${row.reason}-${idx}`}>
                  <td className="cell-mono">
                    <Link to={`/hosts/${encodeURIComponent(row.ip)}`}>
                      {row.ip}
                    </Link>
                  </td>
                  <td>{row.reason}</td>
                  <td className="cell-mono">{row.value}</td>
                  <td>{row.country_code ?? t('common.dash')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {total > limit && (
        <div className="related-hosts-pager">
          <span className="related-hosts-pager-meta">
            {t('hostPage.relatedHostsPagination', { page, pages, total })}
          </span>
          <div className="related-hosts-pager-actions">
            <button
              className="secondary"
              disabled={loading || page <= 1}
              onClick={() => onPageChange(page - 1)}
              type="button"
            >
              <ChevronLeft size={14} aria-hidden />
              {t('common.prev')}
            </button>
            <button
              className="secondary"
              disabled={loading || page >= pages}
              onClick={() => onPageChange(page + 1)}
              type="button"
            >
              {t('common.next')}
              <ChevronRight size={14} aria-hidden />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
