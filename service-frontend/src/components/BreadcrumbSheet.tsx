import * as Dialog from '@radix-ui/react-dialog';
import { ChevronRight } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import {
  BREADCRUMB_ROOT_HREF,
  translateBreadcrumbSegment,
  type BreadcrumbNav,
} from '@app/routes';

type BreadcrumbSheetProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  breadcrumb: BreadcrumbNav;
};

export function BreadcrumbSheet({
  open,
  onOpenChange,
  breadcrumb,
}: BreadcrumbSheetProps) {
  const { t } = useTranslation();

  return (
    <Dialog.Root onOpenChange={onOpenChange} open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay breadcrumb-sheet-overlay" />
        <Dialog.Content
          aria-describedby={undefined}
          className="dialog uv-dialog--sheet breadcrumb-sheet"
        >
          <div className="uv-dialog__handle" />
          <Dialog.Title className="breadcrumb-sheet-title">
            {t('shell.breadcrumbSheetTitle')}
          </Dialog.Title>
          <ol className="breadcrumb-sheet-list">
            <li className="breadcrumb-sheet-item">
              <Link
                className="breadcrumb-sheet-link"
                onClick={() => onOpenChange(false)}
                to={BREADCRUMB_ROOT_HREF}
              >
                uv://
              </Link>
            </li>
            {breadcrumb.segments.map((segment, index) => {
              const href = breadcrumb.hrefs[index];
              const label = translateBreadcrumbSegment(segment, t);
              const isLeaf = index === breadcrumb.segments.length - 1;

              return (
                <li
                  className="breadcrumb-sheet-item"
                  key={`${segment}-${index}`}
                >
                  <ChevronRight
                    aria-hidden
                    className="breadcrumb-sheet-sep"
                    size={14}
                  />
                  {href !== undefined && !isLeaf ? (
                    <Link
                      className="breadcrumb-sheet-link"
                      onClick={() => onOpenChange(false)}
                      to={href}
                    >
                      {label}
                    </Link>
                  ) : (
                    <span className="breadcrumb-sheet-leaf">{label}</span>
                  )}
                </li>
              );
            })}
          </ol>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
