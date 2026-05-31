import * as Dialog from '@radix-ui/react-dialog';
import { Keyboard } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { SheetDragHandle } from './SheetDragHandle';
import { useIsPhablet } from '@/hooks/useBreakpoint';

type ShortcutsOverlayProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

type ShortcutEntry = {
  keys: string[];
  labelKey: string;
};

type ShortcutGroup = {
  titleKey: string;
  entries: ShortcutEntry[];
};

const GROUPS: ShortcutGroup[] = [
  {
    titleKey: 'shortcuts.groupGlobal',
    entries: [
      { keys: ['?'], labelKey: 'shortcuts.entryHelp' },
      { keys: ['⌘', 'K'], labelKey: 'shortcuts.entryPalette' },
    ],
  },
  {
    titleKey: 'shortcuts.groupNavigation',
    entries: [
      { keys: ['g', 'h'], labelKey: 'shortcuts.entryGoDashboard' },
      { keys: ['g', 's'], labelKey: 'shortcuts.entryGoScans' },
      { keys: ['g', 'q'], labelKey: 'shortcuts.entryGoSearch' },
      { keys: ['g', 'a'], labelKey: 'shortcuts.entryGoAlerts' },
    ],
  },
  {
    titleKey: 'shortcuts.groupTables',
    entries: [
      { keys: ['j', '↓'], labelKey: 'shortcuts.entryRowDown' },
      { keys: ['k', '↑'], labelKey: 'shortcuts.entryRowUp' },
      { keys: ['Enter'], labelKey: 'shortcuts.entryActivate' },
      { keys: ['x'], labelKey: 'shortcuts.entryToggleSelect' },
    ],
  },
];

export function ShortcutsOverlay({ open, onOpenChange }: ShortcutsOverlayProps) {
  const { t } = useTranslation();
  const isPhablet = useIsPhablet();

  return (
    <Dialog.Root onOpenChange={onOpenChange} open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content
          className={`dialog shortcuts-overlay uv-anim-pop${isPhablet ? ' uv-dialog--sheet' : ''}`}
        >
          {isPhablet && (
            <SheetDragHandle onDismiss={() => onOpenChange(false)} />
          )}
          <div className="shortcuts-overlay-header">
            <span aria-hidden className="shortcuts-overlay-icon">
              <Keyboard size={18} />
            </span>
            <Dialog.Title className="shortcuts-overlay-title">
              {t('shortcuts.title')}
            </Dialog.Title>
          </div>
          <Dialog.Description className="shortcuts-overlay-description">
            {t('shortcuts.description')}
          </Dialog.Description>

          <div className="shortcuts-overlay-body">
            {GROUPS.map((group) => (
              <section className="shortcuts-group" key={group.titleKey}>
                <h3 className="shortcuts-group-title">{t(group.titleKey)}</h3>
                <ul className="shortcuts-list">
                  {group.entries.map((entry) => (
                    <li className="shortcuts-row" key={entry.labelKey}>
                      <span className="shortcuts-row-label">
                        {t(entry.labelKey)}
                      </span>
                      <span className="shortcuts-row-keys">
                        {entry.keys.map((key, idx) => (
                          <kbd
                            className="shortcuts-kbd"
                            key={`${entry.labelKey}-${idx}`}
                          >
                            {key}
                          </kbd>
                        ))}
                      </span>
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </div>

          <div className="shortcuts-overlay-actions">
            <Dialog.Close asChild>
              <button className="secondary" type="button">
                {t('common.close')}
              </button>
            </Dialog.Close>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
