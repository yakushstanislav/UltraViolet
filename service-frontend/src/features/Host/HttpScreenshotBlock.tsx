import * as Dialog from '@radix-ui/react-dialog';
import axios from 'axios';
import { Camera, Expand, ImageOff, Loader2, X } from 'lucide-react';
import { useCallback, useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { getHostHttpScreenshot } from '@services/HostAPI';

type HttpScreenshotBlockProps = {
  hostIp: string;
  serviceId: number;
};

type LoadState = 'idle' | 'loading' | 'ready' | 'error';

// Screenshots aren't synced with the page load lifecycle; they're rendered by
// a background worker after each HTTP probe. Auto-load once on mount so the
// square thumbnail appears next to the HTTP response. Click opens a modal.
export function HttpScreenshotBlock({
  hostIp,
  serviceId,
}: HttpScreenshotBlockProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [state, setState] = useState<LoadState>('idle');
  const [error, setError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const load = useCallback(
    async (controller: AbortController) => {
      setState('loading');
      setError(null);

      try {
        const blob = await getHostHttpScreenshot(
          hostIp,
          serviceId,
          controller.signal
        );

        if (controller.signal.aborted) {
          return;
        }

        const url = URL.createObjectURL(blob);
        setImageUrl((prev) => {
          if (prev !== null) {
            URL.revokeObjectURL(prev);
          }

          return url;
        });
        setState('ready');
      } catch (err) {
        if (axios.isCancel(err) || controller.signal.aborted) {
          return;
        }

        if (axios.isAxiosError(err) && err.response?.status === 404) {
          setError(
            t('http.screenshot.pending', 'Screenshot not yet rendered.')
          );
        } else if (axios.isAxiosError(err)) {
          setError(
            err.message || t('http.screenshot.error', 'Failed to load screenshot.')
          );
        } else {
          setError(t('http.screenshot.error', 'Failed to load screenshot.'));
        }

        setState('error');
      }
    },
    [hostIp, serviceId, t]
  );

  useEffect(() => {
    const controller = new AbortController();

    void load(controller);

    return () => {
      controller.abort();
    };
  }, [load]);

  useEffect(() => {
    return () => {
      setImageUrl((prev) => {
        if (prev !== null) {
          URL.revokeObjectURL(prev);
        }

        return null;
      });
    };
  }, []);

  return (
    <section aria-labelledby={titleId} className="http-screenshot-root">
      <header className="http-screenshot-header">
        <div aria-hidden className="http-screenshot-header-icon">
          <Camera size={14} strokeWidth={1.75} />
        </div>
        <h4 className="http-screenshot-title" id={titleId}>
          {t('http.screenshot.title', 'Page screenshot')}
        </h4>
      </header>

      <div className="http-screenshot-body">
        {state === 'loading' && (
          <figure
            aria-live="polite"
            className="http-screenshot-thumb-wrap http-screenshot-thumb-wrap--placeholder"
          >
            <Loader2 aria-hidden className="animate-spin" size={20} />
          </figure>
        )}

        {state === 'ready' && imageUrl !== null && (
          <figure className="http-screenshot-thumb-wrap">
            <div
              aria-haspopup="dialog"
              aria-label={t('http.screenshot.expand', 'Open full size')}
              className="http-screenshot-thumb-btn"
              onClick={() => {
                setModalOpen(true);
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  setModalOpen(true);
                }
              }}
              role="button"
              tabIndex={0}
            >
              <img
                alt={t('http.screenshot.alt', 'HTTP service screenshot')}
                className="http-screenshot-thumb-img"
                src={imageUrl}
              />
              <span aria-hidden className="http-screenshot-thumb-overlay">
                <Expand size={18} strokeWidth={1.75} />
              </span>
            </div>
          </figure>
        )}

        {state === 'error' && (
          <>
            <figure
              className="http-screenshot-thumb-wrap http-screenshot-thumb-wrap--placeholder"
              role="status"
            >
              <ImageOff aria-hidden size={20} strokeWidth={1.25} />
            </figure>
            <p className="http-screenshot-error-text">{error}</p>
          </>
        )}
      </div>

      {state === 'ready' && imageUrl !== null && (
        <Dialog.Root onOpenChange={setModalOpen} open={modalOpen}>
          <Dialog.Portal>
            <Dialog.Overlay className="dialog-overlay" />
            <Dialog.Content
              aria-describedby={undefined}
              className="dialog http-screenshot-modal"
            >
              <div className="http-screenshot-modal-header">
                <Dialog.Title className="http-screenshot-modal-title">
                  {t('http.screenshot.title', 'Page screenshot')}
                </Dialog.Title>
                <Dialog.Close asChild>
                  <button
                    aria-label={t('http.screenshot.close', 'Close screenshot')}
                    className="secondary http-screenshot-modal-close"
                    type="button"
                  >
                    <X aria-hidden size={18} strokeWidth={1.75} />
                  </button>
                </Dialog.Close>
              </div>
              <div className="http-screenshot-modal-body">
                <img
                  alt={t('http.screenshot.alt', 'HTTP service screenshot')}
                  className="http-screenshot-modal-img"
                  src={imageUrl}
                />
              </div>
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
      )}
    </section>
  );
}
