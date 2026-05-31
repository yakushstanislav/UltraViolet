import { Check, Copy } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { copyTextToClipboard } from '@helpers/clipboard';
import { showActionError } from '@helpers/uiError';

type CopyButtonProps = {
  text: string;
  label?: string;
  copiedLabel?: string;
  className?: string;
  size?: number;
  /** When true, only the icon is shown (label still used for aria-label). */
  iconOnly?: boolean;
  disabled?: boolean;
};

export function CopyButton({
  text,
  label,
  copiedLabel,
  className,
  size = 14,
  iconOnly = false,
  disabled = false,
}: CopyButtonProps) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const resetTimerRef = useRef<number | null>(null);

  const resolvedLabel = label ?? t('common.copy');
  const resolvedCopiedLabel = copiedLabel ?? t('common.copied');

  useEffect(() => {
    return () => {
      if (resetTimerRef.current !== null) {
        window.clearTimeout(resetTimerRef.current);
      }
    };
  }, []);

  const handleClick = useCallback(() => {
    copyTextToClipboard(
      text,
      () => {
        setCopied(true);
        if (resetTimerRef.current !== null) {
          window.clearTimeout(resetTimerRef.current);
        }
        resetTimerRef.current = window.setTimeout(() => {
          setCopied(false);
          resetTimerRef.current = null;
        }, 2000);
      },
      () => {
        showActionError(null, 'common.copyFailed');
      }
    );
  }, [text]);

  return (
    <button
      aria-label={copied ? resolvedCopiedLabel : resolvedLabel}
      className={className ?? 'secondary'}
      disabled={disabled}
      onClick={handleClick}
      type="button"
    >
      {copied ? (
        <>
          <Check aria-hidden size={size} />
          {!iconOnly && resolvedCopiedLabel}
        </>
      ) : (
        <>
          <Copy aria-hidden size={size} />
          {!iconOnly && resolvedLabel}
        </>
      )}
    </button>
  );
}
