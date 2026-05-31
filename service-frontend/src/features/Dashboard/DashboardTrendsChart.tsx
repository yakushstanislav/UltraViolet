import { TrendingUp } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { DashboardWidgetTools } from '@components/DashboardWidgetTools';
import { EmptyState } from '@components/EmptyState';
import { getDashboardTrends } from '@services/DashboardAPI';
import type {
  DashboardTrendsRange,
  DashboardTrendsResponse,
} from '@/types/api';

type Series = {
  labelKey: string;
  color: string;
  key: keyof Pick<
    DashboardTrendsResponse['points'][number],
    | 'scans_created'
    | 'scans_completed'
    | 'hosts_discovered'
    | 'change_new'
    | 'change_disappeared'
    | 'change_changed'
  >;
};

const SERIES: readonly Series[] = [
  {
    labelKey: 'dashboard.trendSeriesScansCreated',
    color: '#3b82f6',
    key: 'scans_created',
  },
  {
    labelKey: 'dashboard.trendSeriesScansCompleted',
    color: '#22c55e',
    key: 'scans_completed',
  },
  {
    labelKey: 'dashboard.trendSeriesHostsDiscovered',
    color: '#a855f7',
    key: 'hosts_discovered',
  },
  {
    labelKey: 'dashboard.trendSeriesChangeNew',
    color: '#10b981',
    key: 'change_new',
  },
  {
    labelKey: 'dashboard.trendSeriesChangeDisappeared',
    color: '#ef4444',
    key: 'change_disappeared',
  },
  {
    labelKey: 'dashboard.trendSeriesChangeChanged',
    color: '#f59e0b',
    key: 'change_changed',
  },
];

const SPARK_W = 120;
const SPARK_H = 22;

function sparklinePath(values: number[]): { line: string; lastX: number; lastY: number } | null {
  if (values.length === 0) {
    return null;
  }

  const max = Math.max(0, ...values);
  const stepX = values.length > 1 ? SPARK_W / (values.length - 1) : 0;

  const points = values.map((v, i) => {
    const x = values.length === 1 ? SPARK_W / 2 : i * stepX;
    const y = max === 0 ? SPARK_H - 1 : SPARK_H - 1 - (v / max) * (SPARK_H - 2);

    return { x, y };
  });

  const line = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
    .join(' ');

  const last = points[points.length - 1] ?? { x: 0, y: 0 };

  return { line, lastX: last.x, lastY: last.y };
}

type DashboardTrendsChartProps = {
  range: DashboardTrendsRange;
};

export function DashboardTrendsChart({ range }: DashboardTrendsChartProps) {
  const { t } = useTranslation();
  const [data, setData] = useState<DashboardTrendsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await getDashboardTrends({ range });
      setData(res);
      setLastUpdated(new Date());
    } catch (err: unknown) {
      setData(null);
      setError(
        err instanceof Error ? err.message : t('dashboard.trendsLoadFailed')
      );
    } finally {
      setLoading(false);
    }
  }, [range, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const points = data?.points ?? [];

  const rangeLabel = (() => {
    if (range === '24h') {
      return t('dashboard.trendsRange24h');
    }

    if (range === '30d') {
      return t('dashboard.trendsRange30d');
    }

    return t('dashboard.trendsRange7d');
  })();

  return (
    <section
      aria-label={t('dashboard.trendsAria')}
      className="dashboard-panel dashboard-trends"
    >
      <header className="dashboard-panel-header">
        <h2 className="dashboard-panel-title">
          {t('dashboard.trendsTitle')}
          <span className="dashboard-trends-range-badge">{rangeLabel}</span>
        </h2>
        <DashboardWidgetTools
          lastUpdated={lastUpdated}
          loading={loading}
          onRefresh={() => void reload()}
        />
      </header>
      {error && <div className="error">{error}</div>}
      {loading && !data && <div className="dashboard-panel-skeleton" />}
      {!loading && points.length === 0 && (
        <EmptyState
          icon={<TrendingUp aria-hidden size={20} />}
          title={t('dashboard.trendsEmpty')}
        />
      )}
      {points.length > 0 && (
        <ul className="dashboard-trend-grid">
          {SERIES.map((series) => {
            const values = points.map((p) => p[series.key]);
            const total = values.reduce((acc, v) => acc + v, 0);
            const spark = sparklinePath(values);

            return (
              <li className="dashboard-trend-row" key={series.key}>
                <span className="dashboard-trend-meta">
                  <span
                    aria-hidden
                    className="dashboard-trend-dot"
                    style={{ background: series.color }}
                  />
                  <span className="dashboard-trend-label">
                    {t(series.labelKey)}
                  </span>
                </span>
                <svg
                  aria-hidden
                  className="dashboard-trend-sparkline"
                  preserveAspectRatio="none"
                  viewBox={`0 0 ${String(SPARK_W)} ${String(SPARK_H)}`}
                >
                  {spark && (
                    <>
                      <path
                        d={spark.line}
                        fill="none"
                        stroke={series.color}
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={1.5}
                      />
                      <circle
                        cx={spark.lastX}
                        cy={spark.lastY}
                        fill={series.color}
                        r={2}
                      />
                    </>
                  )}
                </svg>
                <strong className="dashboard-trend-total">
                  {total.toLocaleString()}
                </strong>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
