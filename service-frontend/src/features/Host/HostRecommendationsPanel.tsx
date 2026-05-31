import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { isAbortError } from '@helpers/abortError';
import { listHostRecommendations } from '@services/RiskRecommendationsAPI';
import type { Recommendation } from '@/types/recommendations';

type HostRecommendationsPanelProps = {
  ip: string;
};

export function HostRecommendationsPanel({ ip }: HostRecommendationsPanelProps) {
  const { t } = useTranslation();
  const [items, setItems] = useState<Recommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    setLoading(true);
    setError(null);

    listHostRecommendations(ip, 50, controller.signal)
      .then((response) => setItems(response.recommendations ?? []))
      .catch((err: unknown) => {
        if (isAbortError(err)) {
          return;
        }

        setError(t('risk.recommendations.errorLoading'));
      })
      .finally(() => setLoading(false));

    return () => controller.abort();
  }, [ip, t]);

  const uniqueItems = useMemo(() => {
    const seen = new Map<string, Recommendation>();

    for (const rec of items) {
      const key = `${rec.action_code}|${rec.label}`;

      if (!seen.has(key)) {
        seen.set(key, rec);
      }
    }

    return Array.from(seen.values());
  }, [items]);

  const totalDelta = useMemo(
    () =>
      uniqueItems.reduce((sum, row) => sum + (row.expected_delta_score ?? 0), 0),
    [uniqueItems],
  );

  if (loading) {
    return (
      <section className="panel host-recommendations">
        <header className="panel-head">
          <h2>{t('risk.recommendations.title')}</h2>
        </header>
        <p className="host-recommendations-meta">{t('common.loading')}</p>
      </section>
    );
  }

  if (error != null) {
    return (
      <section className="panel host-recommendations">
        <header className="panel-head">
          <h2>{t('risk.recommendations.title')}</h2>
        </header>
        <p className="host-recommendations-meta">{error}</p>
      </section>
    );
  }

  if (items.length === 0) {
    return (
      <section className="panel host-recommendations">
        <header className="panel-head">
          <h2>{t('risk.recommendations.title')}</h2>
        </header>
        <p className="host-recommendations-meta">
          {t('risk.recommendations.empty')}
        </p>
      </section>
    );
  }

  return (
    <section className="panel host-recommendations">
      <header className="panel-head host-recommendations-head">
        <h2>{t('risk.recommendations.title')}</h2>
        <span className="host-recommendations-meta">
          {t('risk.recommendations.totalDelta', { value: -totalDelta })}
        </span>
      </header>

      <ul className="host-recommendations-list">
        {uniqueItems.map((rec) => (
          <li className="host-recommendation" key={rec.id}>
            <span className="host-recommendation-label">{rec.label}</span>
            <span className="host-recommendation-delta">
              −{rec.expected_delta_score}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
