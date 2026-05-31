import axios from 'axios';
import { Video, Wand2 } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';

import { CopyButton } from '@components/CopyButton';
import i18n from '@i18n/i18n';
import { postHostRTSPSnapshot } from '@services/HostAPI';

type WireTransport = 'tcp' | 'udp';

export type RtspPathCue = {
  path: string;
  nonce: number;
};

type RtspSnapshotBlockProps = {
  hostIp: string;
  port: number;
  /** Matches scanned `uv_service.transport`; defaults to TCP. */
  defaultWireTransport?: WireTransport;
  /** When `nonce` changes, replaces the stream path field (e.g. from ONVIF GetStreamUri). */
  pathCue?: RtspPathCue | null;
};

/** Host part for rtsp:// authority (IPv6 literals need brackets). */
function rtspAuthorityHost(hostIp: string): string {
  if (hostIp.includes(':')) {
    return `[${hostIp}]`;
  }

  return hostIp;
}

function formatRtspSnapshotUserMessage(
  translate: TFunction,
  code: string | undefined
): string {
  const key =
    code !== undefined && code !== '' ? (`rtsp.errors.${code}` as const) : null;

  if (key !== null && i18n.exists(key)) {
    return translate(key);
  }

  return code !== undefined && code !== ''
    ? code
    : translate('rtsp.errors.requestFailed');
}

export function RtspSnapshotBlock({
  hostIp,
  port,
  defaultWireTransport = 'tcp',
  pathCue = null,
}: RtspSnapshotBlockProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const pathFieldId = useId();
  const userFieldId = useId();
  const passwordFieldId = useId();
  const [path, setPath] = useState('/');
  const [user, setUser] = useState('');
  const [password, setPassword] = useState('');
  const [transport, setTransport] = useState<WireTransport>(() =>
    defaultWireTransport === 'udp' ? 'udp' : 'tcp'
  );
  const [loading, setLoading] = useState(false);
  const [requestKind, setRequestKind] = useState<'exact' | 'auto' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const lastPathCueNonce = useRef<number | null>(null);

  useEffect(() => {
    lastPathCueNonce.current = null;
    setPath('/');
    setUser('');
    setPassword('');
    setError(null);
    setImageUrl((prev) => {
      if (prev !== null) {
        URL.revokeObjectURL(prev);
      }

      return null;
    });
  }, [port]);

  useEffect(() => {
    return () => {
      if (imageUrl !== null) {
        URL.revokeObjectURL(imageUrl);
      }
    };
  }, [imageUrl]);

  useEffect(() => {
    setTransport(defaultWireTransport === 'udp' ? 'udp' : 'tcp');
  }, [defaultWireTransport, port]);

  useEffect(() => {
    if (pathCue === null || pathCue.path === '') {
      return;
    }

    if (lastPathCueNonce.current === pathCue.nonce) {
      return;
    }

    lastPathCueNonce.current = pathCue.nonce;
    setPath(pathCue.path);
  }, [pathCue]);

  const handleCapture = async (kind: 'exact' | 'auto') => {
    setError(null);
    setLoading(true);
    setRequestKind(kind);

    if (imageUrl !== null) {
      URL.revokeObjectURL(imageUrl);
      setImageUrl(null);
    }

    try {
      const { blob, resolvedPath } = await postHostRTSPSnapshot(hostIp, {
        port,
        path,
        transport,
        auto_try_common_paths: kind === 'auto' ? true : undefined,
        user: user === '' ? undefined : user,
        password: password === '' ? undefined : password,
      });

      if (resolvedPath !== undefined && resolvedPath !== '') {
        setPath(resolvedPath);
      }

      const url = URL.createObjectURL(blob);
      setImageUrl(url);
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.data instanceof Blob) {
        try {
          const text = await err.response.data.text();
          const parsed = JSON.parse(text) as {
            error?: string;
            reason?: string;
          };
          setError(
            formatRtspSnapshotUserMessage(t, parsed.reason ?? parsed.error)
          );
        } catch {
          setError(t('rtsp.errors.requestFailed'));
        }
      } else if (axios.isAxiosError(err)) {
        setError(err.message);
      } else {
        setError(t('rtsp.errors.requestFailed'));
      }
    } finally {
      setLoading(false);
      setRequestKind(null);
    }
  };

  const rtspUrlNoCreds = `rtsp://${rtspAuthorityHost(hostIp)}:${port}${path.startsWith('/') ? path : `/${path}`}`;

  return (
    <section aria-labelledby={titleId} className="rtsp-snapshot-root">
      <div className="rtsp-snapshot-card">
        <header className="rtsp-snapshot-header">
          <div aria-hidden className="rtsp-snapshot-header-icon">
            <Video size={20} strokeWidth={1.75} />
          </div>
          <div className="rtsp-snapshot-header-copy">
            <h3 className="rtsp-snapshot-title" id={titleId}>
              {t('rtsp.title')}
            </h3>
            <p className="rtsp-snapshot-lead">{t('rtsp.lead')}</p>
          </div>
          <span className="rtsp-snapshot-port-pill">
            {transport.toUpperCase()} {port}
          </span>
        </header>

        <div className="rtsp-snapshot-callout" role="note">
          <span className="rtsp-snapshot-callout-dot" aria-hidden />
          <p>{t('rtsp.authorizationCallout')}</p>
        </div>

        <div className="rtsp-snapshot-form">
          <div className="rtsp-snapshot-field rtsp-snapshot-field-full rtsp-snapshot-transport-field">
            <div className="rtsp-snapshot-label-row rtsp-snapshot-transport-label">
              <span
                className="rtsp-snapshot-label-text"
                id={`${titleId}-transport`}
              >
                {t('rtsp.wireTransport')}
              </span>
              <span className="rtsp-snapshot-label-hint">
                {t('rtsp.wireTransportHint')}
              </span>
            </div>
            <div
              aria-labelledby={`${titleId}-transport`}
              className="segmented-control rtsp-snapshot-transport-seg"
              role="group"
            >
              {(['tcp', 'udp'] as const).map((value) => (
                <button
                  className={
                    transport === value ? 'segmented-active' : 'secondary'
                  }
                  key={value}
                  onClick={() => {
                    setTransport(value);
                  }}
                  type="button"
                >
                  {value.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          <label
            className="rtsp-snapshot-field rtsp-snapshot-field-full"
            htmlFor={pathFieldId}
          >
            <span className="rtsp-snapshot-label-text">
              {t('rtsp.streamPath')}
            </span>
            <input
              autoComplete="off"
              id={pathFieldId}
              onChange={(e) => {
                setPath(e.target.value);
              }}
              placeholder="/"
              spellCheck={false}
              type="text"
              value={path}
            />
          </label>
          <label className="rtsp-snapshot-field" htmlFor={userFieldId}>
            <span className="rtsp-snapshot-label-row">
              <span className="rtsp-snapshot-label-text">
                {t('rtsp.username')}
              </span>
              <span className="rtsp-snapshot-label-hint">
                {t('common.optional')}
              </span>
            </span>
            <input
              autoComplete="username"
              id={userFieldId}
              onChange={(e) => {
                setUser(e.target.value);
              }}
              spellCheck={false}
              type="text"
              value={user}
            />
          </label>
          <label className="rtsp-snapshot-field" htmlFor={passwordFieldId}>
            <span className="rtsp-snapshot-label-row">
              <span className="rtsp-snapshot-label-text">
                {t('rtsp.password')}
              </span>
              <span className="rtsp-snapshot-label-hint">
                {t('common.optional')}
              </span>
            </span>
            <input
              autoComplete="current-password"
              id={passwordFieldId}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
              spellCheck={false}
              type="password"
              value={password}
            />
          </label>
        </div>

        <div className="rtsp-snapshot-toolbar">
          <button
            aria-busy={loading}
            className="primary rtsp-snapshot-capture"
            disabled={loading || path === ''}
            onClick={() => {
              void handleCapture('exact');
            }}
            type="button"
          >
            {loading && requestKind === 'exact' ? (
              <>
                <span className="rtsp-snapshot-spinner" aria-hidden />
                {t('rtsp.capturing')}
              </>
            ) : (
              <>
                <Video aria-hidden size={17} strokeWidth={2} />
                {t('rtsp.captureFrame')}
              </>
            )}
          </button>
          <button
            aria-busy={loading}
            className="secondary rtsp-snapshot-auto-paths"
            disabled={loading}
            onClick={() => {
              void handleCapture('auto');
            }}
            title={t('rtsp.tryCommonPathsTitle')}
            type="button"
          >
            {loading && requestKind === 'auto' ? (
              <>
                <span className="rtsp-snapshot-spinner" aria-hidden />
                {t('rtsp.tryingPaths')}
              </>
            ) : (
              <>
                <Wand2 aria-hidden size={17} strokeWidth={2} />
                {t('rtsp.tryCommonPaths')}
              </>
            )}
          </button>
          <CopyButton
            className="secondary rtsp-snapshot-copy"
            disabled={loading}
            label={t('rtsp.copyRtspUrl')}
            size={17}
            text={rtspUrlNoCreds}
          />
        </div>

        {loading && <div aria-hidden className="rtsp-snapshot-progress" />}

        <div aria-live="polite" className="rtsp-snapshot-live">
          {error !== null && (
            <div className="rtsp-snapshot-error" role="alert">
              {error}
            </div>
          )}
        </div>

        <figure
          className={`rtsp-snapshot-preview ${imageUrl !== null ? 'rtsp-snapshot-preview--has-image' : ''}`}
        >
          {imageUrl !== null ? (
            <>
              <img
                alt={t('rtsp.frameAlt')}
                className="rtsp-snapshot-image"
                src={imageUrl}
              />
              <figcaption className="rtsp-snapshot-caption">
                {t('rtsp.latestCapture')}
              </figcaption>
            </>
          ) : (
            <figcaption className="rtsp-snapshot-placeholder">
              <span className="rtsp-snapshot-placeholder-icon" aria-hidden>
                <Video size={28} strokeWidth={1.25} />
              </span>
              <span className="rtsp-snapshot-placeholder-text">
                {t('rtsp.previewPlaceholder')}
              </span>
            </figcaption>
          )}
        </figure>
      </div>
    </section>
  );
}
