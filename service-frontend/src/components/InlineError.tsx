import { AlertCircle, RotateCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';

type InlineErrorProps = {
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
};

export function InlineError({ message, onRetry, retryLabel }: InlineErrorProps) {
  const { t } = useTranslation();

  return (
    <div aria-live="polite" className="inline-error error" role="alert">
      <span aria-hidden className="inline-error-icon">
        <AlertCircle size={16} />
      </span>
      <span className="inline-error-message">{message}</span>
      {onRetry && (
        <button
          className="inline-error-retry secondary"
          onClick={onRetry}
          type="button"
        >
          <RotateCw aria-hidden size={14} />
          {retryLabel ?? t('common.retry')}
        </button>
      )}
    </div>
  );
}
