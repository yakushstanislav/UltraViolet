import * as Popover from '@radix-ui/react-popover';
import { KeyRound, MoreHorizontal, Power, PowerOff } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { useDemoMode } from '@/hooks/useDemoMode';

type UserRowMenuProps = {
  active: boolean;
  canToggleActive: boolean;
  onResetPassword: () => void;
  onToggleActive: () => void;
};

export function UserRowMenu({
  active,
  canToggleActive,
  onResetPassword,
  onToggleActive,
}: UserRowMenuProps) {
  const { t } = useTranslation();
  const demoMode = useDemoMode();
  const [open, setOpen] = useState(false);

  const pick = (action: () => void) => {
    setOpen(false);
    action();
  };

  return (
    <Popover.Root onOpenChange={setOpen} open={open}>
      <Popover.Trigger asChild>
        <button
          aria-label={t('adminUsers.actionsMenuLabel')}
          className="secondary users-actions-trigger"
          type="button"
        >
          <MoreHorizontal aria-hidden size={16} />
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          className="role-select-menu users-actions-menu"
          collisionPadding={12}
          side="bottom"
          sideOffset={6}
        >
          <div className="role-select-menu-inner" role="menu">
            <button
              className="role-select-option"
              disabled={demoMode}
              onClick={() => pick(onResetPassword)}
              role="menuitem"
              type="button"
            >
              <span className="role-select-option-label">
                <KeyRound aria-hidden size={14} />
                {t('adminUsers.resetPassword')}
              </span>
            </button>
            <button
              className="role-select-option"
              disabled={!canToggleActive}
              onClick={() => pick(onToggleActive)}
              role="menuitem"
              type="button"
            >
              <span className="role-select-option-label">
                {active ? (
                  <PowerOff aria-hidden size={14} />
                ) : (
                  <Power aria-hidden size={14} />
                )}
                {active
                  ? t('adminUsers.disableUser')
                  : t('adminUsers.enableUser')}
              </span>
            </button>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
