import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ProbabilityBar } from '@components/ProbabilityBar';
import { isAbortError } from '@helpers/abortError';
import { getServiceRiskExplain } from '@services/HostAPI';
import type { ServiceRiskExplain } from '@/types/risk';

type ServiceExplainDisclosureProps = {
  serviceId: number;
  label: string;
};

export function ServiceExplainDisclosure({
  serviceId,
  label,
}: ServiceExplainDisclosureProps) {
  const [open, setOpen] = useState(false);
  const className = open
    ? 'service-explain-toggle service-explain-toggle-open'
    : 'service-explain-toggle';

  return (
    <>
      <button
        aria-expanded={open}
        className={className}
        onClick={() => setOpen((current) => !current)}
        type="button"
      >
        {label}
      </button>
      {open && (
        <div className="service-explain-row">
          <ServiceExplainContent serviceId={serviceId} />
        </div>
      )}
    </>
  );
}

type ServiceExplainContentProps = {
  serviceId: number;
};

function ServiceExplainContent({ serviceId }: ServiceExplainContentProps) {
  const { t } = useTranslation();
  const [explain, setExplain] = useState<ServiceRiskExplain | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    setLoading(true);
    setError(null);

    getServiceRiskExplain(serviceId, controller.signal)
      .then((data) => setExplain(data))
      .catch((err: unknown) => {
        if (isAbortError(err)) {
          return;
        }

        setError(t('risk.explain.noSignals'));
      })
      .finally(() => setLoading(false));

    return () => controller.abort();
  }, [serviceId, t]);

  if (loading) {
    return (
      <div className="service-explain-inline service-explain-inline-loading">
        <p className="host-risk-explain-meta">{t('common.loading')}</p>
      </div>
    );
  }

  if (error != null) {
    return (
      <div className="service-explain-inline">
        <p className="host-risk-explain-meta">{error}</p>
      </div>
    );
  }

  if (explain == null) {
    return null;
  }

  const channels = (explain.channels ?? [])
    .slice()
    .sort((a, b) => b.p - a.p);
  const probabilityPct = Math.round(explain.probability * 100);
  const recencyPct = Math.round(explain.recency_factor * 100);

  return (
    <div className="service-explain-inline">
      <div className="service-explain-stats">
        <span className="service-explain-stat">
          <span className="service-explain-stat-label">
            {t('risk.explain.stat.probability')}
          </span>
          <span className="service-explain-stat-value">{probabilityPct}%</span>
        </span>
        <span className="service-explain-stat">
          <span className="service-explain-stat-label">
            {t('risk.explain.recency')}
          </span>
          <span className="service-explain-stat-value">{recencyPct}%</span>
        </span>
      </div>

      {channels.length > 0 ? (
        <ul className="service-explain-channel-list">
          {channels.map((channel) => {
            const pct = Math.round(channel.p * 100);
            const isZero = channel.p <= 0;

            return (
              <li
                className={
                  isZero
                    ? 'service-explain-channel service-explain-channel-empty'
                    : 'service-explain-channel'
                }
                key={channel.code}
              >
                <span className="service-explain-channel-label">
                  {channel.label}
                </span>
                <ProbabilityBar percent value={pct} />
                <span className="service-explain-channel-value">{pct}%</span>
                {channel.sources != null && channel.sources.length > 0 && (
                  <span className="service-explain-channel-sources">
                    {channel.sources.join(' · ')}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="host-risk-explain-meta">{t('risk.explain.noSignals')}</p>
      )}
    </div>
  );
}
