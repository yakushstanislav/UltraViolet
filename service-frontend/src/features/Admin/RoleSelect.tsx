import * as Popover from '@radix-ui/react-popover';
import clsx from 'clsx';
import { Check, ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { AppRole } from '@/types/users';

const ROLES: AppRole[] = ['viewer', 'operator', 'admin'];

type RoleSelectProps = {
  value: AppRole;
  onChange: (role: AppRole) => void;
  compact?: boolean;
  disabled?: boolean;
  id?: string;
  'aria-label'?: string;
};

export function RoleSelect({
  value,
  onChange,
  compact = false,
  disabled = false,
  id,
  'aria-label': ariaLabel,
}: RoleSelectProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);

  const pickRole = (role: AppRole) => {
    onChange(role);
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
          aria-label={ariaLabel ?? t('adminUsers.role')}
          className={clsx(
            'role-select-trigger',
            `user-role-select-${value}`,
            compact && 'role-select-trigger-compact'
          )}
          disabled={disabled}
          id={id}
          type="button"
        >
          <span className="role-select-trigger-label">
            {t(`adminUsers.roleLabels.${value}`)}
          </span>
          <ChevronDown
            aria-hidden
            className="role-select-trigger-caret"
            size={compact ? 16 : 18}
          />
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="start"
          className="role-select-menu"
          collisionPadding={12}
          side="bottom"
          sideOffset={6}
        >
          <div className="role-select-menu-inner" role="listbox">
            {ROLES.map((role) => {
              const selected = role === value;

              return (
                <button
                  aria-selected={selected}
                  className={clsx(
                    'role-select-option',
                    selected && 'role-select-option-selected'
                  )}
                  key={role}
                  onClick={() => pickRole(role)}
                  role="option"
                  type="button"
                >
                  <span>{t(`adminUsers.roleLabels.${role}`)}</span>
                  {selected ? (
                    <Check aria-hidden className="role-select-option-check" size={14} />
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
