import { ChevronDown, Network, ShieldAlert } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { showActionError } from '@helpers/uiError';
import { getHostRiskExplain } from '@services/HostAPI';
import type { HostRiskExplainResponse } from '@/types/pivot';

import { HostRiskExplain } from './HostRiskExplain';
import { riskScoreClass, riskTier } from './hostRiskHelpers';

type HostRiskPanelProps = {
  ip: string;
  riskScore: number;
};

export function HostRiskPanel({ ip, riskScore }: HostRiskPanelProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [explain, setExplain] = useState<HostRiskExplainResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const tier = riskTier(riskScore);
  const scoreClass = riskScoreClass(riskScore);

  useEffect(() => {
    setExplain(null);
    setOpen(false);
  }, [ip]);

  const loadExplain = async () => {
    if (explain) {
      setOpen((current) => !current);

      return;
    }

    if (loading) {
      return;
    }

    setLoading(true);

    try {
      const response = await getHostRiskExplain(ip);
      setExplain(response);
      setOpen(true);
    } catch (err: unknown) {
      showActionError(err, 'common.loadFailed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <section aria-label={t('hostPage.riskPanelAria')} className="panel host-risk-panel">
      <div className="host-risk-toolbar">
        <span aria-hidden className="host-risk-head-icon">
          <ShieldAlert size={14} />
        </span>
        <div className="host-risk-head-copy">
          <h2>{t('hostPage.attackSurfaceScore')}</h2>
          <p className="host-risk-head-hint">{t('hostPage.riskHeadHint')}</p>
        </div>
        <div className="host-risk-toolbar-end">
          <p className={`host-risk-panel-score ${scoreClass}`}>{riskScore}</p>
          <span className={`risk-badge ${scoreClass}`}>
            {t(`hostPage.riskTier.${tier}`)}
          </span>
          <Link
            className="host-attack-path-link"
            to={`/attack-paths/${encodeURIComponent(ip)}`}
          >
            <Network aria-hidden size={14} />
            {t('hostPage.viewAttackPath')}
          </Link>
          <button
            aria-expanded={open}
            className="host-risk-why-btn"
            disabled={loading}
            onClick={() => {
              void loadExplain();
            }}
            type="button"
          >
            {loading ? t('common.loading') : t('hostPage.riskWhy')}
            <span aria-hidden className="host-risk-chevron-wrap">
              <ChevronDown
                className={open ? 'host-risk-chevron host-risk-chevron-open' : 'host-risk-chevron'}
                size={13}
                strokeWidth={2.25}
              />
            </span>
          </button>
        </div>
      </div>

      <div aria-hidden className="host-risk-panel-bar">
        <div
          className={`host-risk-panel-bar-fill ${scoreClass}`}
          style={{ width: `${String(Math.min(100, Math.max(0, riskScore)))}%` }}
        />
      </div>

      {open && explain && <HostRiskExplain explain={explain} />}
    </section>
  );
}
