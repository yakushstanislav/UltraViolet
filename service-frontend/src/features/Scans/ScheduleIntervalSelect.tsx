import * as Popover from '@radix-ui/react-popover';
import clsx from 'clsx';
import { Check, ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  SCAN_SCHEDULE_INTERVAL_OPTIONS,
} from './scanScheduleIntervals';

type ScheduleIntervalSelectProps = {
  value: number;
  onChange: (seconds: number) => void;
  disabled?: boolean;
  id?: string;
  'aria-label'?: string;
};

export function ScheduleIntervalSelect({
  value,
  onChange,
  disabled = false,
  id,
  'aria-label': ariaLabel,
}: ScheduleIntervalSelectProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);

  const selected = SCAN_SCHEDULE_INTERVAL_OPTIONS.find(
    (opt) => opt.seconds === value
  );
  const label = selected
    ? t(selected.labelKey)
    : t('scanSchedules.interval');

  const pickInterval = (seconds: number) => {
    onChange(seconds);
    setOpen(false);
  };

  return (
    <Popover.Root
      onOpenChange={(next) => {
        if (!disabled) {
          setOpen(next);
        }
      }}
      open={disabled ? false : open}
    >
      <Popover.Trigger asChild>
        <button
          aria-expanded={open}
          aria-haspopup="listbox"
          aria-label={ariaLabel ?? t('scanSchedules.interval')}
          className="schedule-interval-trigger"
          disabled={disabled}
          id={id}
          type="button"
        >
          <span className="schedule-interval-trigger-label">{label}</span>
          <ChevronDown
            aria-hidden
            className="schedule-interval-trigger-caret"
            size={18}
          />
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="start"
          className="schedule-interval-menu"
          collisionPadding={12}
          side="bottom"
          sideOffset={6}
        >
          <div className="schedule-interval-menu-inner" role="listbox">
            {SCAN_SCHEDULE_INTERVAL_OPTIONS.map((opt) => {
              const isSelected = opt.seconds === value;

              return (
                <button
                  aria-selected={isSelected}
                  className={clsx(
                    'schedule-interval-option',
                    isSelected && 'schedule-interval-option-selected'
                  )}
                  key={opt.seconds}
                  onClick={() => pickInterval(opt.seconds)}
                  role="option"
                  type="button"
                >
                  <span>{t(opt.labelKey)}</span>
                  {isSelected ? (
                    <Check
                      aria-hidden
                      className="schedule-interval-option-check"
                      size={14}
                    />
                  ) : null}
                </button>
              );
            })}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
