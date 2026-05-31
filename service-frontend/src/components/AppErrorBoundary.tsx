import { AlertOctagon, RefreshCw, RotateCcw } from 'lucide-react';
import { Component, type ErrorInfo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import { isChunkLoadError } from '@helpers/chunkLoadError';

type Props = {
  fallback?: ReactNode;
  children: ReactNode;
  resetKey?: string;
};

type State = {
  error: Error | null;
};

type FallbackProps = {
  error: Error;
  onReset: () => void;
  onReload: () => void;
};

function ErrorBoundaryFallback({ error, onReset, onReload }: FallbackProps) {
  const { t } = useTranslation();
  const message = error.message.trim();
  const stack = error.stack;
  const chunkStale = isChunkLoadError(error);

  return (
    <section className="page error-boundary-page">
      <div className="error-boundary-panel" role="alert">
        <div aria-hidden className="error-boundary-icon">
          <AlertOctagon size={28} strokeWidth={1.75} />
        </div>
        <div className="error-boundary-body">
          <h2 className="error-boundary-title">{t('errorBoundary.title')}</h2>
          <p className="error-boundary-description">
            {chunkStale
              ? t('errorBoundary.chunkStaleDescription')
              : t('errorBoundary.description')}
          </p>
          {message.length > 0 ? (
            <div className="error-boundary-message">
              <span className="error-boundary-message-label">
                {t('errorBoundary.errorLabel')}
              </span>
              <code className="error-boundary-message-text">{message}</code>
            </div>
          ) : null}
          {stack !== undefined && stack.length > 0 ? (
            <details className="error-boundary-details">
              <summary>{t('errorBoundary.showDetails')}</summary>
              <pre className="error-boundary-stack">{stack}</pre>
            </details>
          ) : null}
          <div className="error-boundary-actions">
            <button onClick={onReset} type="button">
              <RotateCcw aria-hidden size={14} strokeWidth={2.25} />
              {chunkStale
                ? t('errorBoundary.reloadPage')
                : t('errorBoundary.reloadView')}
            </button>
            <button className="secondary" onClick={onReload} type="button">
              <RefreshCw aria-hidden size={14} strokeWidth={2.25} />
              {t('errorBoundary.reloadPage')}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

export class AppErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('AppErrorBoundary caught error:', error, info);
  }

  componentDidUpdate(prevProps: Props): void {
    if (
      this.state.error !== null &&
      prevProps.resetKey !== this.props.resetKey
    ) {
      this.setState({ error: null });
    }
  }

  handleReset = (): void => {
    if (this.state.error !== null && isChunkLoadError(this.state.error)) {
      window.location.reload();

      return;
    }

    this.setState({ error: null });
  };

  handleReload = (): void => {
    window.location.reload();
  };

  render(): ReactNode {
    const { error } = this.state;

    if (error === null) {
      return this.props.children;
    }

    if (this.props.fallback !== undefined) {
      return this.props.fallback;
    }

    return (
      <ErrorBoundaryFallback
        error={error}
        onReload={this.handleReload}
        onReset={this.handleReset}
      />
    );
  }
}
