import * as Dialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { ReactNode } from 'react';

import { DialogSheetContent } from './DialogSheetContent';

type DetailDrawerProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
};

export function DetailDrawer({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
}: DetailDrawerProps) {
  const { t } = useTranslation();

  return (
    <Dialog.Root onOpenChange={onOpenChange} open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogSheetContent
          className="detail-drawer"
          onDismiss={() => onOpenChange(false)}
        >
          <header className="detail-drawer-head">
            <div>
              <Dialog.Title className="detail-drawer-title">{title}</Dialog.Title>
              {description !== undefined && description !== '' && (
                <Dialog.Description className="detail-drawer-desc">
                  {description}
                </Dialog.Description>
              )}
            </div>
            <Dialog.Close className="dialog-close" aria-label={t('common.close')}>
              <X aria-hidden size={16} />
            </Dialog.Close>
          </header>
          <div className="detail-drawer-body">{children}</div>
          {footer !== undefined && (
            <footer className="detail-drawer-footer">{footer}</footer>
          )}
        </DialogSheetContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
