import { useTranslation } from 'react-i18next';

import { ProbabilityBar } from '@/components/ProbabilityBar';
import { RiskScoreBadge } from '@/components/RiskScoreBadge';
import type { HostRiskExplainResponse } from '@/types/pivot';
import type { RiskBucket } from '@/types/risk';

type HostRiskExplainProps = {
  explain: HostRiskExplainResponse;
};

export function HostRiskExplain({ explain }: HostRiskExplainProps) {
  const { t } = useTranslation();
  const factors = explain.factors ?? [];
  const channels = explain.channels ?? [];
  const impacts = explain.impacts ?? [];
  const hasChannels = channels.length > 0;
  const hasImpacts = impacts.length > 0;
  const hasMeters = explain.confidence_meters != null;
  const probabilityPct =
    explain.probability != null ? Math.round(explain.probability * 100) : null;
  const impactPct =
    explain.impact != null ? Math.round(explain.impact * 100) : null;
  const confidencePct =
    explain.confidence != null ? Math.round(explain.confidence * 100) : null;

  const hasStats =
    probabilityPct != null || impactPct != null || confidencePct != null;

  return (
    <div className="host-risk-explain">
      <div className="host-risk-explain-header">
        <RiskScoreBadge
          score={explain.risk_score}
          bucket={explain.bucket as RiskBucket | undefined}
        />
        <p className="host-risk-explain-updated">
          {t('risk.explain.updatedAt', {
            when: explain.updated_at ?? t('common.na'),
          })}
        </p>
      </div>

      {hasStats && (
        <div className="host-risk-stats" role="group" aria-label={t('risk.explain.title')}>
          {probabilityPct != null && (
            <RiskStatCard
              label={t('risk.explain.stat.probability')}
              value={probabilityPct}
            />
          )}
          {impactPct != null && (
            <RiskStatCard
              label={t('risk.explain.stat.impact')}
              value={impactPct}
            />
          )}
          {confidencePct != null && (
            <RiskStatCard
              label={t('risk.explain.stat.confidence')}
              value={confidencePct}
            />
          )}
        </div>
      )}

      {factors.length > 0 && (
        <>
          <p className="host-risk-explain-title">{t('hostPage.riskFactors')}</p>
          <ul className="host-risk-factor-list">
            {factors.map((factor) => (
              <li
                className={
                  factor.weight >= 20
                    ? 'host-risk-factor-chip host-risk-factor-chip-heavy'
                    : 'host-risk-factor-chip'
                }
                key={factor.code}
              >
                <span>{factor.label}</span>
                {factor.weight > 0 && <strong>+{factor.weight}</strong>}
              </li>
            ))}
          </ul>
        </>
      )}

      {hasChannels && (
        <>
          <p className="host-risk-explain-title">
            {t('risk.explain.channels')}
          </p>
          <ul className="host-risk-channel-list">
            {channels.map((channel) => (
              <li className="host-risk-channel-row" key={channel.code}>
                <div className="host-risk-channel-head">
                  <span className="host-risk-channel-label">{channel.label}</span>
                  <span className="host-risk-channel-p">
                    {Math.round(channel.p * 100)}%
                  </span>
                </div>
                <ProbabilityBar value={channel.p} />
                {channel.sources != null && channel.sources.length > 0 && (
                  <p className="host-risk-channel-sources">
                    {channel.sources.join(' · ')}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </>
      )}

      {hasImpacts && (
        <>
          <p className="host-risk-explain-title">
            {t('risk.explain.impacts')}
          </p>
          <ul className="host-risk-impact-list">
            {impacts.map((impact) => (
              <li className="host-risk-impact-row" key={impact.code}>
                <span className="host-risk-impact-label">{impact.label}</span>
                <span className="host-risk-impact-contribution">
                  {(impact.contribution * 100).toFixed(1)}%
                </span>
              </li>
            ))}
          </ul>
        </>
      )}

      {hasMeters && (
        <>
          <p className="host-risk-explain-title">
            {t('risk.explain.confidence')}
          </p>
          <dl className="host-risk-meters">
            <ConfidenceMeter
              label={t('risk.explain.completeness')}
              value={explain.confidence_meters!.completeness}
            />
            <ConfidenceMeter
              label={t('risk.explain.recency')}
              value={explain.confidence_meters!.recency}
            />
            <ConfidenceMeter
              label={t('risk.explain.signalQuality')}
              value={explain.confidence_meters!.signal_quality}
            />
            <ConfidenceMeter
              label={t('risk.explain.tagCompleteness')}
              value={explain.confidence_meters!.tag_completeness}
            />
          </dl>
        </>
      )}

      {explain.components != null && (
        <dl className="host-risk-components">
          <div>
            <dt>{t('hostPage.riskMaxService')}</dt>
            <dd>{explain.components.max_service_risk}</dd>
          </div>
          <div>
            <dt>{t('hostPage.riskServiceCount')}</dt>
            <dd>{explain.components.service_count}</dd>
          </div>
          <div>
            <dt>{t('hostPage.riskHighRiskServices')}</dt>
            <dd>{explain.components.high_risk_service_count}</dd>
          </div>
          <div>
            <dt>{t('hostPage.riskKevCount')}</dt>
            <dd>{explain.components.kev_count}</dd>
          </div>
          <div>
            <dt>{t('hostPage.riskCriticalCves')}</dt>
            <dd>{explain.components.critical_cve_count}</dd>
          </div>
        </dl>
      )}
    </div>
  );
}

type RiskStatCardProps = {
  label: string;
  value: number;
};

function RiskStatCard({ label, value }: RiskStatCardProps) {
  return (
    <div className="host-risk-stat">
      <span className="host-risk-stat-label">{label}</span>
      <span className="host-risk-stat-value">{value}%</span>
      <ProbabilityBar percent value={value} />
    </div>
  );
}

type ConfidenceMeterProps = {
  label: string;
  value: number;
};

function ConfidenceMeter({ label, value }: ConfidenceMeterProps) {
  const pct = Math.round(value * 100);

  return (
    <div className="host-risk-meter">
      <dt>{label}</dt>
      <dd>
        <ProbabilityBar percent value={pct} />
        <span className="host-risk-meter-value">{pct}%</span>
      </dd>
    </div>
  );
}
