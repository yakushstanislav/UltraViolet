import { useTranslation } from 'react-i18next';

import { bucketForScore, type RiskBucket } from '@/types/risk';

type RiskScoreBadgeProps = {
  score: number;
  bucket?: RiskBucket | string;
  prevScore?: number;
  showDelta?: boolean;
  size?: 'sm' | 'md';
};

export function RiskScoreBadge({
  score,
  bucket,
  prevScore,
  showDelta = false,
  size = 'md',
}: RiskScoreBadgeProps) {
  const { t } = useTranslation();
  const effectiveBucket = bucket ?? bucketForScore(score);
  const className = `risk-badge risk-${effectiveBucket}${size === 'sm' ? ' risk-badge-sm' : ''}`;
  const delta = showDelta && prevScore != null ? score - prevScore : null;
  const ariaLabel = t('risk.score', { score, bucket: t(`risk.bucket.${effectiveBucket}`) });

  return (
    <span className="risk-score-badge-group" aria-label={ariaLabel}>
      <span className={className}>{score}</span>
      <span className="risk-bucket-label">{t(`risk.bucket.${effectiveBucket}`)}</span>
      {delta != null && delta !== 0 && (
        <span
          className={`risk-score-delta ${delta > 0 ? 'risk-score-delta-up' : 'risk-score-delta-down'}`}
          aria-label={t('risk.delta', { value: delta > 0 ? `+${delta}` : `${delta}` })}
        >
          {delta > 0 ? `+${delta}` : delta}
        </span>
      )}
    </span>
  );
}
