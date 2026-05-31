import * as Popover from '@radix-ui/react-popover';
import { LogOut, MoreHorizontal, Moon, ShieldCheck, Sun } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { AppRole } from '@/types/users';
import { useTheme } from '@/theme/ThemeProvider';

type TopbarOverflowMenuProps = {
  role: AppRole | null;
  roleLabel: string;
  roleClass: string;
  onLogout: () => void;
};

export function TopbarOverflowMenu({
  role,
  roleLabel,
  roleClass,
  onLogout,
}: TopbarOverflowMenuProps) {
  const { t } = useTranslation();
  const { theme, toggleTheme } = useTheme();
  const [open, setOpen] = useState(false);

  const pick = (action: () => void) => {
    setOpen(false);
    action();
  };

  return (
    <Popover.Root onOpenChange={setOpen} open={open}>
      <Popover.Trigger asChild>
        <button
          aria-expanded={open}
          aria-label={t('shell.moreActions')}
          className="topbar-icon-btn topbar-overflow-trigger"
          type="button"
        >
          <MoreHorizontal aria-hidden size={16} />
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          className="topbar-overflow-menu"
          collisionPadding={12}
          side="bottom"
          sideOffset={8}
        >
          <div className="topbar-overflow-menu__inner" role="menu">
            {role && (
              <div
                aria-label={t('shell.signedInAs', { role: roleLabel })}
                className={`topbar-overflow-menu__role ${roleClass}`}
              >
                <span aria-hidden className="topbar-overflow-menu__role-icon">
                  <ShieldCheck size={16} />
                </span>
                <span className="topbar-overflow-menu__role-text">
                  <span className="topbar-overflow-menu__role-caption">
                    {t('adminUsers.role')}
                  </span>
                  <span className="topbar-overflow-menu__role-label">
                    {roleLabel}
                  </span>
                </span>
              </div>
            )}
            <div className="topbar-overflow-menu__actions">
              <button
                className="topbar-overflow-menu__item"
                onClick={() => pick(toggleTheme)}
                role="menuitem"
                type="button"
              >
                <span aria-hidden className="topbar-overflow-menu__item-icon">
                  {theme === 'dark' ? (
                    <Sun size={16} />
                  ) : (
                    <Moon size={16} />
                  )}
                </span>
                <span className="topbar-overflow-menu__item-label">
                  {t('shell.toggleTheme')}
                </span>
              </button>
              <button
                className="topbar-overflow-menu__item topbar-overflow-menu__item--danger"
                onClick={() => pick(onLogout)}
                role="menuitem"
                type="button"
              >
                <span aria-hidden className="topbar-overflow-menu__item-icon">
                  <LogOut size={16} />
                </span>
                <span className="topbar-overflow-menu__item-label">
                  {t('shell.disconnect')}
                </span>
              </button>
            </div>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
