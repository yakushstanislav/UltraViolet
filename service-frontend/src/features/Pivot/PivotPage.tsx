import { GitBranchPlus, Search } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router-dom';

import { EmptyState } from '@components/EmptyState';
import { getPivot } from '@services/PivotAPI';
import type { PivotResponse } from '@/types/pivot';

import { PivotGraph } from './PivotGraph';
import { PivotLegend } from './PivotLegend';
import { pivotSearchParams, pivotStats } from './pivotHelpers';

export function PivotPage() {
  const { kind = '', value = '' } = useParams();
  const { t } = useTranslation();
  const [data, setData] = useState<PivotResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const kindLabel = t(`pivot.kinds.${kind}`, { defaultValue: kind });

  useEffect(() => {
    const controller = new AbortController();

    setLoading(true);
    setError(null);

    void getPivot(kind, value, 200, controller.signal)
      .then((response) => {
        setData(response);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        setError(err instanceof Error ? err.message : t('common.error'));
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });

    return () => {
      controller.abort();
    };
  }, [kind, t, value]);

  const searchHref = `/search?${pivotSearchParams(kind, value).toString()}`;
  const stats = useMemo(
    () => (data ? pivotStats(data) : { hostCount: 0, serviceCount: 0 }),
    [data]
  );
  const graphEmpty = data !== null && stats.serviceCount === 0;

  return (
    <section className="page pivot-page">
      <header className="page-header">
        <div>
          <h1>{t('pivot.title')}</h1>
          <p className="page-subtitle">
            <span className="pivot-kind-badge">{kindLabel}</span>
            <span className="cell-mono pivot-value">{value}</span>
          </p>
        </div>
        <Link className="button button-secondary pivot-search-link" to={searchHref}>
          <Search aria-hidden size={16} />
          {t('pivot.openInSearch')}
        </Link>
      </header>

      {loading && <div className="notice">{t('common.loading')}</div>}
      {error && <div className="error">{error}</div>}

      {!loading && !error && data && (
        <>
          <PivotLegend
            hostCount={stats.hostCount}
            serviceCount={stats.serviceCount}
          />

          {data.truncated && (
            <div className="notice pivot-notice-truncated">
              {t('pivot.truncated', {
                shown: stats.serviceCount,
                total: data.total,
              })}
            </div>
          )}

          {graphEmpty ? (
            <div className="panel pivot-empty-panel">
              <EmptyState
                action={
                  <Link className="button button-secondary" to={searchHref}>
                    {t('pivot.openInSearch')}
                  </Link>
                }
                hint={t('pivot.emptyHint')}
                icon={<GitBranchPlus size={28} />}
                title={t('pivot.emptyTitle')}
              />
            </div>
          ) : (
            <PivotGraph data={data} />
          )}
        </>
      )}
    </section>
  );
}
