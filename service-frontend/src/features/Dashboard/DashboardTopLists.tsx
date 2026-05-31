import { BarChart3 } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';

import { DashboardWidgetTools } from '@components/DashboardWidgetTools';
import { EmptyState } from '@components/EmptyState';
import { Select } from '@components/Select';
import { getDashboardTop } from '@services/DashboardAPI';
import type { DashboardTopResponse } from '@/types/api';

type TabKey = 'ports' | 'protocols' | 'asn' | 'countries' | 'tls';

const TAB_KEYS: TabKey[] = ['ports', 'protocols', 'asn', 'countries', 'tls'];

const TAB_LABEL_KEYS: Record<TabKey, string> = {
  ports: 'dashboard.topTabPorts',
  protocols: 'dashboard.topTabProtocols',
  asn: 'dashboard.topTabAsn',
  countries: 'dashboard.topTabCountries',
  tls: 'dashboard.topTabTls',
};

function BarRow({
  label,
  value,
  max,
}: {
  label: string;
  value: number;
  max: number;
}) {
  const pct = max === 0 ? 0 : Math.min(100, (value / max) * 100);

  return (
    <li className="dashboard-top-row">
      <span className="dashboard-top-label" title={label}>
        {label}
      </span>
      <div className="dashboard-top-bar">
        <div
          className="dashboard-top-bar-fill"
          style={{ width: `${String(pct)}%` }}
        />
      </div>
      <strong className="dashboard-top-value">{value.toLocaleString()}</strong>
    </li>
  );
}

function renderTab(
  tab: TabKey,
  data: DashboardTopResponse,
  translate: TFunction
): { items: { label: string; value: number }[]; emptyText: string } {
  switch (tab) {
    case 'ports':
      return {
        items: data.top_ports.map((p) => ({
          label: String(p.port),
          value: p.count,
        })),
        emptyText: translate('dashboard.topEmptyPorts'),
      };
    case 'protocols':
      return {
        items: data.top_protocols.map((p) => ({
          label: p.protocol,
          value: p.count,
        })),
        emptyText: translate('dashboard.topEmptyProtocols'),
      };
    case 'asn':
      return {
        items: data.top_asn.map((a) => ({
          label: a.asn_org
            ? `AS${String(a.asn)} · ${a.asn_org}`
            : `AS${String(a.asn)}`,
          value: a.count,
        })),
        emptyText: translate('dashboard.topEmptyAsn'),
      };
    case 'countries':
      return {
        items: data.top_countries.map((c) => ({
          label: c.country_code,
          value: c.count,
        })),
        emptyText: translate('dashboard.topEmptyCountries'),
      };
    case 'tls':
      return {
        items: data.top_tls_issuers.map((issuerRow) => ({
          label: issuerRow.issuer,
          value: issuerRow.count,
        })),
        emptyText: translate('dashboard.topEmptyTls'),
      };
  }
}

export function DashboardTopLists() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<TabKey>('ports');
  const [data, setData] = useState<DashboardTopResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const tabs = useMemo(
    () =>
      TAB_KEYS.map((key) => ({
        key,
        label: t(TAB_LABEL_KEYS[key]),
      })),
    [t]
  );

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await getDashboardTop({ limit: 10 });
      setData(res);
      setLastUpdated(new Date());
    } catch (err: unknown) {
      setData(null);
      setError(
        err instanceof Error ? err.message : t('dashboard.topListsLoadFailed')
      );
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const rendered = data ? renderTab(tab, data, t) : null;
  const max = rendered
    ? rendered.items.reduce((acc, item) => Math.max(acc, item.value), 0)
    : 0;

  return (
    <section
      aria-label={t('dashboard.topListsAria')}
      className="dashboard-panel dashboard-top"
    >
      <header className="dashboard-panel-header">
        <h2 className="dashboard-panel-title">
          {t('dashboard.topListsTitle')}
        </h2>
        <Select
          aria-label={t('dashboard.topListsCategoryAria')}
          className="uv-select--pill"
          compact
          matchTriggerWidth={false}
          onChange={(next) => setTab(next as TabKey)}
          options={tabs.map((option) => ({
            value: option.key,
            label: option.label,
          }))}
          value={tab}
        />
        <DashboardWidgetTools
          lastUpdated={lastUpdated}
          loading={loading}
          onRefresh={() => void reload()}
        />
      </header>
      {error && <div className="error">{error}</div>}
      {loading && !data && <div className="dashboard-panel-skeleton" />}
      {!loading && rendered && rendered.items.length === 0 && (
        <EmptyState
          icon={<BarChart3 aria-hidden size={20} />}
          title={rendered.emptyText}
        />
      )}
      {rendered && rendered.items.length > 0 && (
        <ul className="dashboard-top-list">
          {rendered.items.map((item) => (
            <BarRow
              key={item.label}
              label={item.label}
              max={max}
              value={item.value}
            />
          ))}
        </ul>
      )}
    </section>
  );
}
