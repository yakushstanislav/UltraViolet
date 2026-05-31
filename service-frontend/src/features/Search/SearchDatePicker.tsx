import * as Popover from '@radix-ui/react-popover';
import clsx from 'clsx';
import dayjs from 'dayjs';
import isSameOrBefore from 'dayjs/plugin/isSameOrBefore';
import isoWeek from 'dayjs/plugin/isoWeek';
import {
  CalendarDays,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

dayjs.extend(isoWeek);
dayjs.extend(isSameOrBefore);

type Props = {
  name: string;
  /** Local calendar date `YYYY-MM-DD`, derived from URL / RFC3339. */
  isoDate: string;
};

const WEEKDAY_KEYS = ['mo', 'tu', 'we', 'th', 'fr', 'sa', 'su'] as const;

function padCells(gridStart: dayjs.Dayjs, gridEnd: dayjs.Dayjs): dayjs.Dayjs[] {
  const out: dayjs.Dayjs[] = [];

  for (
    let d = gridStart;
    d.isSameOrBefore(gridEnd, 'day');
    d = d.add(1, 'day')
  ) {
    out.push(d);
  }

  return out;
}

export function SearchDatePicker({ name, isoDate }: Props) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState(isoDate);
  const [cursor, setCursor] = useState(() =>
    isoDate ? dayjs(isoDate) : dayjs()
  );

  useEffect(() => {
    setValue(isoDate);
    setCursor(isoDate ? dayjs(isoDate) : dayjs());
  }, [isoDate]);

  const labelText = useMemo(() => {
    if (!value) {
      return t('searchDatePicker.anyDate');
    }

    return dayjs(value).format('D MMM YYYY');
  }, [t, value]);

  const monthYear = cursor.format('MMMM YYYY');
  const ymKey = cursor.format('YYYY-MM');
  const cells = useMemo(() => {
    const monthStart = dayjs(ymKey + '-01');
    const gridStart = monthStart.startOf('isoWeek');
    const gridEnd = monthStart.endOf('month').endOf('isoWeek');

    return padCells(gridStart, gridEnd);
  }, [ymKey]);

  const pickDay = (d: dayjs.Dayjs) => {
    const next = d.format('YYYY-MM-DD');
    setValue(next);
    setOpen(false);
  };

  const clear = () => {
    setValue('');
    setOpen(false);
  };

  return (
    <>
      <input name={name} type="hidden" value={value} />
      <Popover.Root open={open} onOpenChange={setOpen}>
        <Popover.Trigger asChild>
          <button
            aria-haspopup="dialog"
            aria-label={t('searchDatePicker.pickDate')}
            className="search-country-trigger search-date-picker-trigger"
            type="button"
          >
            <CalendarDays
              aria-hidden
              className="search-date-picker-trigger-icon"
              size={16}
            />
            <span className="search-country-trigger-text">{labelText}</span>
            <ChevronDown
              aria-hidden
              className="search-country-trigger-caret"
              size={18}
            />
          </button>
        </Popover.Trigger>
        <Popover.Portal>
          <Popover.Content
            align="start"
            className="search-date-picker-popover"
            collisionPadding={12}
            sideOffset={6}
          >
            <div className="search-date-picker-head">
              <button
                aria-label={t('searchDatePicker.prevMonth')}
                className="search-date-picker-nav"
                onClick={() => setCursor((c) => c.subtract(1, 'month'))}
                type="button"
              >
                <ChevronLeft size={18} />
              </button>
              <div className="search-date-picker-month">{monthYear}</div>
              <button
                aria-label={t('searchDatePicker.nextMonth')}
                className="search-date-picker-nav"
                onClick={() => setCursor((c) => c.add(1, 'month'))}
                type="button"
              >
                <ChevronRight size={18} />
              </button>
            </div>
            <div className="search-date-picker-weekdays">
              {WEEKDAY_KEYS.map((w) => (
                <div className="search-date-picker-weekday" key={w}>
                  {t(`searchDatePicker.weekdays.${w}`)}
                </div>
              ))}
            </div>
            <div className="search-date-picker-grid">
              {cells.map((d) => {
                const key = d.format('YYYY-MM-DD');
                const inMonth = d.month() === cursor.month();
                const selected = value !== '' && key === value;
                const today = d.isSame(dayjs(), 'day');

                return (
                  <button
                    className={clsx(
                      'search-date-picker-day',
                      !inMonth && 'search-date-picker-day-muted',
                      selected && 'search-date-picker-day-selected',
                      today && !selected && 'search-date-picker-day-today'
                    )}
                    key={key}
                    onClick={() => pickDay(d)}
                    type="button"
                  >
                    {d.date()}
                  </button>
                );
              })}
            </div>
            <div className="search-date-picker-footer">
              <button
                className="secondary search-date-picker-clear"
                disabled={value === ''}
                onClick={clear}
                type="button"
              >
                {t('searchDatePicker.clear')}
              </button>
            </div>
          </Popover.Content>
        </Popover.Portal>
      </Popover.Root>
    </>
  );
}
