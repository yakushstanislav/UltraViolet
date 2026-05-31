import { Shuffle } from 'lucide-react';
import { useTranslation } from 'react-i18next';

type Size = 'sm' | 'md';

interface Props {
  hostLimit?: number | null;
  size?: Size;
  className?: string;
}

export function RandomTargetBadge({
  hostLimit,
  size = 'sm',
  className,
}: Props) {
  const { t, i18n } = useTranslation();

  const showLimit =
    typeof hostLimit === 'number' &&
    Number.isFinite(hostLimit) &&
    hostLimit > 0;

  const formattedLimit = showLimit
    ? hostLimit.toLocaleString(i18n.language)
    : null;

  const title = showLimit
    ? t('scansPage.randomBadgeTitleWithLimit', { limit: formattedLimit })
    : t('scansPage.randomBadgeTitle');

  const classes = ['random-target-badge', `random-target-badge-${size}`];

  if (className) {
    classes.push(className);
  }

  return (
    <span className={classes.join(' ')} title={title}>
      <Shuffle
        aria-hidden
        className="random-target-badge-icon"
        size={size === 'md' ? 14 : 12}
      />
      <span className="random-target-badge-label">
        {t('scansPage.randomLabel')}
      </span>
      {showLimit && (
        <>
          <span aria-hidden className="random-target-badge-sep">
            ·
          </span>
          <span className="random-target-badge-limit">
            <span className="random-target-badge-limit-label">
              {t('scansPage.randomBadgeLimitLabel')}
            </span>
            <span className="random-target-badge-value">{formattedLimit}</span>
          </span>
        </>
      )}
    </span>
  );
}
