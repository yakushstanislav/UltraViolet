import dayjs from 'dayjs';
import { useTranslation } from 'react-i18next';

import { dateInputToRFC3339 } from './searchFormHelpers';

type SearchLastSeenPresetsProps = {
  onApply: (from: string, to: string) => void;
};

const CALENDAR_DAY_PRESETS = [
  { days: 7, labelKey: 'searchDatePicker.preset7d' },
  { days: 30, labelKey: 'searchDatePicker.preset30d' },
  { days: 90, labelKey: 'searchDatePicker.preset90d' },
] as const;

export function SearchLastSeenPresets({ onApply }: SearchLastSeenPresetsProps) {
  const { t } = useTranslation();

  const applyRollingHours = (hours: number) => {
    const to = dayjs().toISOString();
    const from = dayjs().subtract(hours, 'hour').toISOString();

    onApply(from, to);
  };

  const applyCalendarDays = (days: number) => {
    const to = dayjs().endOf('day');
    const from = dayjs().subtract(days, 'day').startOf('day');
    const fromIso = dateInputToRFC3339(from.format('YYYY-MM-DD'), false);
    const toIso = dateInputToRFC3339(to.format('YYYY-MM-DD'), true);

    if (fromIso === '' || toIso === '') {
      return;
    }

    onApply(fromIso, toIso);
  };

  return (
    <div className="search-date-presets" role="group">
      <span className="search-date-presets-label">
        {t('searchDatePicker.quickPresets')}
      </span>
      <div className="search-date-presets-row">
        <button
          className="secondary search-date-preset-btn"
          onClick={() => applyRollingHours(24)}
          type="button"
        >
          {t('searchDatePicker.preset24h')}
        </button>
        {CALENDAR_DAY_PRESETS.map(({ days, labelKey }) => (
          <button
            className="secondary search-date-preset-btn"
            key={days}
            onClick={() => applyCalendarDays(days)}
            type="button"
          >
            {t(labelKey)}
          </button>
        ))}
      </div>
    </div>
  );
}
