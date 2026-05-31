import * as Dialog from '@radix-ui/react-dialog';
import i18n from '@i18n/i18n';
import { Loader2 } from 'lucide-react';
import { useState, type ReactNode } from 'react';

import { SheetDragHandle } from './SheetDragHandle';
import { useIsPhablet } from '@/hooks/useBreakpoint';

export type ConfirmDialogTone = 'danger' | 'warning' | 'primary';

type ConfirmDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  icon?: ReactNode;
  tone?: ConfirmDialogTone;
  confirmLabel: string;
  confirmIcon?: ReactNode;
  cancelLabel?: string;
  onConfirm: () => void | Promise<void>;
  children?: ReactNode;
};

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  icon,
  tone = 'primary',
  confirmLabel,
  confirmIcon,
  cancelLabel,
  onConfirm,
  children,
}: ConfirmDialogProps) {
  const [submitting, setSubmitting] = useState(false);
  const isPhablet = useIsPhablet();
  const resolvedCancelLabel = cancelLabel ?? i18n.t('common.cancel');

  const confirmButtonClass = tone === 'danger' ? 'danger' : '';

  const handleConfirm = async () => {
    if (submitting) {
      return;
    }

    try {
      setSubmitting(true);
      await onConfirm();
      onOpenChange(false);
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenChange = (next: boolean) => {
    if (submitting && !next) {
      return;
    }

    onOpenChange(next);
  };

  return (
    <Dialog.Root onOpenChange={handleOpenChange} open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay confirm-dialog-overlay" />
        <Dialog.Content
          {...(description ? {} : { 'aria-describedby': undefined })}
          className={`dialog confirm-dialog${isPhablet ? ' uv-dialog--sheet' : ''}`}
          onEscapeKeyDown={(event) => {
            if (submitting) {
              event.preventDefault();
            }
          }}
          onInteractOutside={(event) => {
            if (submitting) {
              event.preventDefault();
            }
          }}
        >
          {isPhablet && (
            <SheetDragHandle
              disabled={submitting}
              onDismiss={() => handleOpenChange(false)}
            />
          )}
          <div className="confirm-dialog-header">
            {icon && (
              <div
                aria-hidden
                className={`confirm-dialog-icon confirm-dialog-icon-${tone}`}
              >
                {icon}
              </div>
            )}
            <div className="confirm-dialog-heading">
              <Dialog.Title className="confirm-dialog-title">
                {title}
              </Dialog.Title>
              {description && (
                <Dialog.Description className="confirm-dialog-description">
                  {description}
                </Dialog.Description>
              )}
            </div>
          </div>

          {children && <div className="confirm-dialog-body">{children}</div>}

          <div className="confirm-dialog-actions">
            <Dialog.Close asChild>
              <button className="secondary" disabled={submitting} type="button">
                {resolvedCancelLabel}
              </button>
            </Dialog.Close>
            <button
              autoFocus
              className={confirmButtonClass}
              disabled={submitting}
              onClick={() => void handleConfirm()}
              type="button"
            >
              {submitting ? (
                <Loader2 aria-hidden className="spin" size={16} />
              ) : (
                confirmIcon
              )}
              {confirmLabel}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
