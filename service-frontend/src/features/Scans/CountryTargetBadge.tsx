import { useTranslation } from 'react-i18next';

import { countryCodeToFlagEmoji } from '@helpers/countryFlagEmoji';

type Size = 'sm' | 'md';

interface Props {
  country: string;
  hostLimit?: number | null;
  size?: Size;
  className?: string;
}

export function CountryTargetBadge({
  country,
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

  const flag = countryCodeToFlagEmoji(country);
  const display = flag ? `${flag} ${country.toUpperCase()}` : country.toUpperCase();

  const title = showLimit
    ? t('scansPage.countryBadgeTitleWithLimit', {
        country: country.toUpperCase(),
        limit: formattedLimit,
      })
    : t('scansPage.countryBadgeTitle', { country: country.toUpperCase() });

  const classes = ['country-target-badge', `country-target-badge-${size}`];

  if (className) {
    classes.push(className);
  }

  return (
    <span className={classes.join(' ')} title={title}>
      <span className="country-target-badge-label">{display}</span>
      {showLimit && (
        <>
          <span aria-hidden className="country-target-badge-sep">
            ·
          </span>
          <span className="country-target-badge-limit">
            <span className="country-target-badge-limit-label">
              {t('scansPage.randomBadgeLimitLabel')}
            </span>
            <span className="country-target-badge-value">{formattedLimit}</span>
          </span>
        </>
      )}
    </span>
  );
}
