import * as Dialog from '@radix-ui/react-dialog';
import { forwardRef, type ComponentPropsWithoutRef, type ReactNode } from 'react';

import { SheetDragHandle } from './SheetDragHandle';
import { useIsPhablet } from '@/hooks/useBreakpoint';

type DialogSheetContentProps = ComponentPropsWithoutRef<typeof Dialog.Content> & {
  className?: string;
  children: ReactNode;
  onDismiss?: () => void;
};

export const DialogSheetContent = forwardRef<HTMLDivElement, DialogSheetContentProps>(
  function DialogSheetContent(
    { className = '', children, onDismiss, ...props },
    ref
  ) {
    const isPhablet = useIsPhablet();
    const sheetClass = isPhablet ? ' uv-dialog--sheet' : '';

    return (
      <Dialog.Content
        ref={ref}
        className={`dialog${className ? ` ${className}` : ''}${sheetClass}`}
        {...props}
      >
        {isPhablet && onDismiss !== undefined && (
          <SheetDragHandle onDismiss={onDismiss} />
        )}
        {children}
      </Dialog.Content>
    );
  }
);
