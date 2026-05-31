import axios from 'axios';
import { Image as ImageIcon, RadioTower } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';

import { CopyButton } from '@components/CopyButton';
import { Select } from '@components/Select';
import {
  postHostOnvifCommand,
  postHostOnvifRtspSnapshot,
} from '@services/HostAPI';
import type { ONVIFAuthMode, ONVIFCommandRequest } from '@/types/hosts';

import { OnvifLabProbe } from './onvif/OnvifLabProbe';
import {
  COMMAND_ORDER,
  formatOnvifUserMessage,
  httpStatusTone,
  isOnvifImagingCommand,
  isOnvifMediaCommand,
  isOnvifPTZCommand,
  needsProfileToken,
  needsVideoSourceToken,
  onvifCommandLabel,
  profileTokensFromParsed,
  videoSourceTokensFromParsed,
  videoSourceTokensFromXml,
} from './onvif/onvifHelpers';

type OnvifCommandBlockProps = {
  hostIp: string;
  port: number;
  /** Prefer https when the scanned service captured TLS metadata. */
  defaultScheme?: 'http' | 'https';
  /** Fills the RTSP snapshot stream path on the matching RTSP service row. */
  onRtspStreamSuggested?: (spec: { port: number; path: string }) => void;
};

export function OnvifCommandBlock({
  hostIp,
  port,
  defaultScheme = 'http',
  onRtspStreamSuggested,
}: OnvifCommandBlockProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const commandFieldId = useId();
  const schemeFieldId = useId();
  const pathFieldId = useId();
  const mediaPathFieldId = useId();
  const imagingPathFieldId = useId();
  const ptzPathFieldId = useId();
  const profileTokenFieldId = useId();
  const videoSourceTokenFieldId = useId();
  const authModeFieldId = useId();
  const responseShapeFieldId = useId();
  const userFieldId = useId();
  const passwordFieldId = useId();
  const responseTitleId = useId();
  const onvifSnapTransportFieldId = useId();

  const [scheme, setScheme] = useState<'http' | 'https'>(() =>
    defaultScheme === 'https' ? 'https' : 'http'
  );
  const [command, setCommand] = useState<ONVIFCommandRequest['command']>(
    'get_system_date_and_time'
  );
  const [devicePath, setDevicePath] = useState('/onvif/device_service');
  const [mediaServicePath, setMediaServicePath] = useState(
    '/onvif/media_service'
  );
  const [imagingServicePath, setImagingServicePath] = useState(
    '/onvif/imaging_service'
  );
  const [ptzServicePath, setPtzServicePath] = useState('/onvif/ptz_service');
  const [profileToken, setProfileToken] = useState('');
  const [videoSourceToken, setVideoSourceToken] = useState('');
  const [authMode, setAuthMode] = useState<ONVIFAuthMode>('basic');
  const [responseShape, setResponseShape] = useState<'raw' | 'json'>('raw');
  const [user, setUser] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    status_code: number;
    content_type: string;
    body: string;
    truncated: boolean;
    parsed?: Record<string, unknown>;
    parse_warnings?: string[];
  } | null>(null);

  const [onvifSnapTransport, setOnvifSnapTransport] = useState<'tcp' | 'udp'>(
    'tcp'
  );
  const [onvifSnapLoading, setOnvifSnapLoading] = useState(false);
  const [onvifSnapError, setOnvifSnapError] = useState<string | null>(null);
  const [onvifSnapImageUrl, setOnvifSnapImageUrl] = useState<string | null>(
    null
  );
  const onvifSnapControllerRef = useRef<AbortController | null>(null);
  const [lastResultCommand, setLastResultCommand] = useState<
    ONVIFCommandRequest['command'] | null
  >(null);

  useEffect(() => {
    setScheme(defaultScheme === 'https' ? 'https' : 'http');
  }, [defaultScheme, port]);

  useEffect(() => {
    onvifSnapControllerRef.current?.abort();
    onvifSnapControllerRef.current = null;

    setResult(null);
    setLastResultCommand(null);
    setError(null);
    setOnvifSnapError(null);
    setOnvifSnapImageUrl((prevUrl) => {
      if (prevUrl !== null) {
        URL.revokeObjectURL(prevUrl);
      }

      return null;
    });
  }, [hostIp, port]);

  useEffect(() => {
    return () => {
      if (onvifSnapImageUrl !== null) {
        URL.revokeObjectURL(onvifSnapImageUrl);
      }
    };
  }, [onvifSnapImageUrl]);

  useEffect(() => {
    return () => {
      onvifSnapControllerRef.current?.abort();
    };
  }, []);

  const videoTokensFromLast = useMemo(() => {
    if (
      result === null ||
      command !== 'get_video_sources' ||
      lastResultCommand !== 'get_video_sources'
    ) {
      return [];
    }

    const fromParsed = videoSourceTokensFromParsed(result.parsed);
    if (fromParsed.length > 0) {
      return fromParsed;
    }

    return videoSourceTokensFromXml(result.body);
  }, [command, lastResultCommand, result]);

  const profileTokensFromLast = useMemo(() => {
    if (
      command !== 'get_media_profiles' ||
      lastResultCommand !== 'get_media_profiles' ||
      result === null
    ) {
      return [];
    }

    return profileTokensFromParsed(result.parsed);
  }, [command, lastResultCommand, result]);

  const sendDisabled = useMemo(() => {
    if (loading) {
      return true;
    }

    if (isOnvifMediaCommand(command) && mediaServicePath === '') {
      return true;
    }

    if (
      !isOnvifMediaCommand(command) &&
      !isOnvifImagingCommand(command) &&
      !isOnvifPTZCommand(command) &&
      devicePath === ''
    ) {
      return true;
    }

    if (isOnvifImagingCommand(command) && imagingServicePath === '') {
      return true;
    }

    if (isOnvifPTZCommand(command) && ptzServicePath === '') {
      return true;
    }

    if (needsProfileToken(command) && profileToken === '') {
      return true;
    }

    if (needsVideoSourceToken(command) && videoSourceToken === '') {
      return true;
    }

    return false;
  }, [
    command,
    devicePath,
    imagingServicePath,
    loading,
    mediaServicePath,
    profileToken,
    ptzServicePath,
    videoSourceToken,
  ]);

  const handleSend = async () => {
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const body: ONVIFCommandRequest = {
        port,
        scheme,
        transport: 'tcp',
        command,
        auth_mode: authMode,
        ...(responseShape === 'json'
          ? { response_shape: 'json' as const }
          : {}),
        ...(isOnvifMediaCommand(command)
          ? {
              media_service_path:
                mediaServicePath === '' ? undefined : mediaServicePath,
            }
          : isOnvifImagingCommand(command)
            ? {
                imaging_service_path:
                  imagingServicePath === '' ? undefined : imagingServicePath,
              }
            : isOnvifPTZCommand(command)
              ? {
                  ptz_service_path:
                    ptzServicePath === '' ? undefined : ptzServicePath,
                }
              : {
                  device_path: devicePath === '' ? undefined : devicePath,
                }),
        profile_token:
          needsProfileToken(command) && profileToken !== ''
            ? profileToken
            : undefined,
        video_source_token:
          needsVideoSourceToken(command) && videoSourceToken !== ''
            ? videoSourceToken
            : undefined,
        user: user === '' ? undefined : user,
        password: password === '' ? undefined : password,
      };

      const data = await postHostOnvifCommand(hostIp, body);
      setResult(data);
      setLastResultCommand(command);
    } catch (err) {
      if (axios.isAxiosError(err)) {
        const data = err.response?.data;
        if (
          data != null &&
          typeof data === 'object' &&
          !(data instanceof Blob)
        ) {
          const d = data as { error?: string; reason?: string };
          setError(formatOnvifUserMessage(t, d.reason ?? d.error));
        } else {
          setError(err.message);
        }
      } else {
        setError(formatOnvifUserMessage(t, undefined));
      }
    } finally {
      setLoading(false);
    }
  };

  const onvifSnapDisabled = onvifSnapLoading || profileToken.trim() === '';

  const handleOnvifRtspSnapshot = async () => {
    onvifSnapControllerRef.current?.abort();
    const controller = new AbortController();
    onvifSnapControllerRef.current = controller;

    setOnvifSnapError(null);
    setOnvifSnapLoading(true);

    if (onvifSnapImageUrl !== null) {
      URL.revokeObjectURL(onvifSnapImageUrl);
      setOnvifSnapImageUrl(null);
    }

    try {
      const { blob } = await postHostOnvifRtspSnapshot(
        hostIp,
        {
          onvif_port: port,
          scheme,
          media_service_path:
            mediaServicePath === '' ? undefined : mediaServicePath,
          profile_token: profileToken,
          transport: onvifSnapTransport,
          auth_mode: authMode,
          user: user === '' ? undefined : user,
          password: password === '' ? undefined : password,
        },
        controller.signal
      );

      if (controller.signal.aborted) {
        return;
      }

      const url = URL.createObjectURL(blob);
      setOnvifSnapImageUrl(url);
    } catch (err) {
      if (controller.signal.aborted) {
        return;
      }

      if (axios.isAxiosError(err) && err.response?.data instanceof Blob) {
        try {
          const text = await err.response.data.text();
          const parsed = JSON.parse(text) as {
            error?: string;
            reason?: string;
          };
          setOnvifSnapError(
            formatOnvifUserMessage(t, parsed.reason ?? parsed.error)
          );
        } catch {
          setOnvifSnapError(formatOnvifUserMessage(t, undefined));
        }
      } else if (axios.isAxiosError(err)) {
        setOnvifSnapError(err.message);
      } else {
        setOnvifSnapError(formatOnvifUserMessage(t, undefined));
      }
    } finally {
      if (!controller.signal.aborted) {
        setOnvifSnapLoading(false);
      }
    }
  };

  const handleLabMatched = (username: string, password: string) => {
    setUser(username);
    setPassword(password);
    setAuthMode('basic');
  };

  const statusTone =
    result !== null ? httpStatusTone(result.status_code) : 'unknown';

  const suggestRtspFromParsed = () => {
    if (result === null || onRtspStreamSuggested === undefined) {
      return;
    }

    const p = result.parsed;
    const pathRaw = p?.rtsp_path;
    const path = typeof pathRaw === 'string' && pathRaw !== '' ? pathRaw : '/';

    const portRaw = p?.rtsp_port;
    const rtspPort =
      typeof portRaw === 'number' && portRaw > 0 && portRaw <= 65535
        ? portRaw
        : 554;

    onRtspStreamSuggested({ port: rtspPort, path });
  };

  const canSuggestRtsp =
    result !== null &&
    result.status_code >= 200 &&
    result.status_code < 300 &&
    command === 'get_stream_uri' &&
    typeof result.parsed?.rtsp_path === 'string' &&
    result.parsed.rtsp_path !== '';

  const hasOnvifResponseBody = useMemo(
    () => result !== null && result.body.trim() !== '',
    [result]
  );

  return (
    <section aria-labelledby={titleId} className="onvif-command-root">
      <div className="onvif-command-card">
        <header className="onvif-command-header">
          <div aria-hidden className="onvif-command-header-icon">
            <RadioTower size={20} strokeWidth={1.75} />
          </div>
          <div className="onvif-command-header-copy">
            <h3 className="onvif-command-title" id={titleId}>
              {t('onvif.title')}
            </h3>
            <p className="onvif-command-lead">
              <Trans
                components={{
                  code: <code className="onvif-command-code" />,
                  em: <em />,
                  strong: <strong />,
                }}
                i18nKey="onvif.lead"
              />
            </p>
          </div>
          <span className="onvif-command-port-pill">
            <span className="onvif-command-port-pill-dot" aria-hidden />
            {t('onvif.tcpPort', { port })}
          </span>
        </header>

        <div className="onvif-command-callout" role="note">
          <span className="onvif-command-callout-glow" aria-hidden />
          <p>{t('onvif.authorizationCallout')}</p>
        </div>

        <div className="onvif-command-form">
          <div className="onvif-command-section">
            <p className="onvif-command-section-title">
              {t('onvif.sectionEndpoint')}
            </p>
            <div className="onvif-command-form-split">
              <div className="onvif-command-field onvif-command-scheme-field">
                <span className="onvif-command-label-text" id={schemeFieldId}>
                  {t('onvif.scheme')}
                </span>
                <div
                  aria-labelledby={schemeFieldId}
                  className="segmented-control onvif-command-scheme-seg"
                  role="group"
                >
                  {(['http', 'https'] as const).map((value) => (
                    <button
                      className={
                        scheme === value ? 'segmented-active' : 'secondary'
                      }
                      key={value}
                      onClick={() => {
                        setScheme(value);
                      }}
                      type="button"
                    >
                      {value.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
              <div className="onvif-command-field onvif-command-scheme-field">
                <span
                  className="onvif-command-label-text"
                  id={responseShapeFieldId}
                >
                  {t('onvif.response')}
                </span>
                <div
                  aria-labelledby={responseShapeFieldId}
                  className="segmented-control onvif-command-scheme-seg"
                  role="group"
                >
                  {(['raw', 'json'] as const).map((value) => (
                    <button
                      className={
                        responseShape === value
                          ? 'segmented-active'
                          : 'secondary'
                      }
                      key={value}
                      onClick={() => {
                        setResponseShape(value);
                      }}
                      type="button"
                    >
                      {value === 'raw'
                        ? t('onvif.responseRaw')
                        : t('onvif.responseJson')}
                    </button>
                  ))}
                </div>
                <p className="onvif-command-checkbox-hint">
                  <Trans
                    components={{
                      code: <code className="onvif-command-code" />,
                    }}
                    i18nKey="onvif.responseHint"
                  />
                </p>
              </div>
            </div>
          </div>

          <div className="onvif-command-section">
            <p className="onvif-command-section-title">
              {t('onvif.sectionSoap')}
            </p>
            <label
              className="onvif-command-field onvif-command-field-full"
              htmlFor={commandFieldId}
            >
              <span className="onvif-command-label-text">
                {t('onvif.command')}
              </span>
              <Select
                id={commandFieldId}
                onChange={(next) =>
                  setCommand(next as ONVIFCommandRequest['command'])
                }
                options={COMMAND_ORDER.map((cmdValue) => ({
                  value: cmdValue,
                  label: onvifCommandLabel(cmdValue, t),
                }))}
                value={command}
              />
            </label>

            {!isOnvifMediaCommand(command) &&
              !isOnvifImagingCommand(command) &&
              !isOnvifPTZCommand(command) && (
                <label
                  className="onvif-command-field onvif-command-field-full"
                  htmlFor={pathFieldId}
                >
                  <span className="onvif-command-label-row">
                    <span className="onvif-command-label-text">
                      {t('onvif.devicePath')}
                    </span>
                    <span className="onvif-command-label-hint">
                      {t('onvif.override')}
                    </span>
                  </span>
                  <input
                    autoComplete="off"
                    className="onvif-command-input"
                    id={pathFieldId}
                    onChange={(e) => {
                      setDevicePath(e.target.value);
                    }}
                    spellCheck={false}
                    type="text"
                    value={devicePath}
                  />
                </label>
              )}

            {isOnvifMediaCommand(command) && (
              <label
                className="onvif-command-field onvif-command-field-full"
                htmlFor={mediaPathFieldId}
              >
                <span className="onvif-command-label-row">
                  <span className="onvif-command-label-text">
                    {t('onvif.mediaPath')}
                  </span>
                  <span className="onvif-command-label-hint">
                    {t('onvif.override')}
                  </span>
                </span>
                <input
                  autoComplete="off"
                  className="onvif-command-input"
                  id={mediaPathFieldId}
                  onChange={(e) => {
                    setMediaServicePath(e.target.value);
                  }}
                  spellCheck={false}
                  type="text"
                  value={mediaServicePath}
                />
              </label>
            )}

            {isOnvifImagingCommand(command) && (
              <label
                className="onvif-command-field onvif-command-field-full"
                htmlFor={imagingPathFieldId}
              >
                <span className="onvif-command-label-row">
                  <span className="onvif-command-label-text">
                    {t('onvif.imagingPath')}
                  </span>
                  <span className="onvif-command-label-hint">
                    {t('onvif.override')}
                  </span>
                </span>
                <input
                  autoComplete="off"
                  className="onvif-command-input"
                  id={imagingPathFieldId}
                  onChange={(e) => {
                    setImagingServicePath(e.target.value);
                  }}
                  spellCheck={false}
                  type="text"
                  value={imagingServicePath}
                />
              </label>
            )}

            {isOnvifPTZCommand(command) && (
              <label
                className="onvif-command-field onvif-command-field-full"
                htmlFor={ptzPathFieldId}
              >
                <span className="onvif-command-label-row">
                  <span className="onvif-command-label-text">
                    {t('onvif.ptzPath')}
                  </span>
                  <span className="onvif-command-label-hint">
                    {t('onvif.override')}
                  </span>
                </span>
                <input
                  autoComplete="off"
                  className="onvif-command-input"
                  id={ptzPathFieldId}
                  onChange={(e) => {
                    setPtzServicePath(e.target.value);
                  }}
                  spellCheck={false}
                  type="text"
                  value={ptzServicePath}
                />
              </label>
            )}

            {needsProfileToken(command) && (
              <label
                className="onvif-command-field onvif-command-field-full"
                htmlFor={profileTokenFieldId}
              >
                <span className="onvif-command-label-text">
                  {t('onvif.profileToken')}
                </span>
                <input
                  autoComplete="off"
                  className="onvif-command-input"
                  id={profileTokenFieldId}
                  onChange={(e) => {
                    setProfileToken(e.target.value);
                  }}
                  placeholder={t('onvif.profileTokenPh')}
                  spellCheck={false}
                  type="text"
                  value={profileToken}
                />
              </label>
            )}

            {needsVideoSourceToken(command) && (
              <label
                className="onvif-command-field onvif-command-field-full"
                htmlFor={videoSourceTokenFieldId}
              >
                <span className="onvif-command-label-text">
                  {t('onvif.videoSourceToken')}
                </span>
                <input
                  autoComplete="off"
                  className="onvif-command-input"
                  id={videoSourceTokenFieldId}
                  onChange={(e) => {
                    setVideoSourceToken(e.target.value);
                  }}
                  placeholder={t('onvif.videoSourceTokenPh')}
                  spellCheck={false}
                  type="text"
                  value={videoSourceToken}
                />
              </label>
            )}

            {profileTokensFromLast.length > 0 && (
              <div className="onvif-command-field onvif-command-field-full">
                <span className="onvif-command-label-text">
                  {t('onvif.parsedProfileTokens')}
                </span>
                <div className="onvif-command-token-chips">
                  {profileTokensFromLast.map((tok) => (
                    <button
                      className="onvif-command-token-chip"
                      key={tok}
                      onClick={() => {
                        setProfileToken(tok);
                      }}
                      type="button"
                    >
                      {tok}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {videoTokensFromLast.length > 0 && (
              <div className="onvif-command-field onvif-command-field-full">
                <span className="onvif-command-label-text">
                  {t('onvif.parsedVideoSources')}
                </span>
                <div className="onvif-command-token-chips">
                  {videoTokensFromLast.map((tok) => (
                    <button
                      className="onvif-command-token-chip"
                      key={tok}
                      onClick={() => {
                        setVideoSourceToken(tok);
                      }}
                      type="button"
                    >
                      {tok}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="onvif-command-section onvif-command-section--auth">
            <p className="onvif-command-section-title">
              {t('onvif.sectionAuth')}
            </p>
            <div className="onvif-command-auth-stack">
              <label
                className="onvif-command-auth-mode"
                htmlFor={authModeFieldId}
              >
                <span className="onvif-command-label-text">
                  {t('onvif.authMode')}
                </span>
                <Select
                  id={authModeFieldId}
                  onChange={(next) => setAuthMode(next as ONVIFAuthMode)}
                  options={[
                    { value: 'none', label: t('onvif.authNone') },
                    { value: 'basic', label: t('onvif.authBasic') },
                    { value: 'digest', label: t('onvif.authDigest') },
                    { value: 'wsse', label: t('onvif.authWsse') },
                  ]}
                  value={authMode}
                />
              </label>
              <div className="onvif-command-auth-creds">
                <label className="onvif-command-field" htmlFor={userFieldId}>
                  <span className="onvif-command-label-row">
                    <span className="onvif-command-label-text">
                      {t('onvif.username')}
                    </span>
                    <span className="onvif-command-label-hint">
                      {t('common.optional')}
                    </span>
                  </span>
                  <input
                    autoComplete="username"
                    className="onvif-command-input"
                    id={userFieldId}
                    onChange={(e) => {
                      setUser(e.target.value);
                    }}
                    spellCheck={false}
                    type="text"
                    value={user}
                  />
                </label>
                <label
                  className="onvif-command-field"
                  htmlFor={passwordFieldId}
                >
                  <span className="onvif-command-label-row">
                    <span className="onvif-command-label-text">
                      {t('onvif.password')}
                    </span>
                    <span className="onvif-command-label-hint">
                      {t('common.optional')}
                    </span>
                  </span>
                  <input
                    autoComplete="current-password"
                    className="onvif-command-input"
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
            </div>
          </div>

          <OnvifLabProbe
            devicePath={devicePath}
            hostIp={hostIp}
            onMatched={handleLabMatched}
            port={port}
            scheme={scheme}
            user={user}
          />

          <div className="onvif-command-subpanel">
            <p className="onvif-command-section-title">
              {t('onvif.jpegSection')}
            </p>
            <div className="onvif-command-field onvif-command-field-full">
              <p className="onvif-command-checkbox-hint">
                <Trans
                  components={{ code: <code className="onvif-command-code" /> }}
                  i18nKey="onvif.jpegHint"
                />
              </p>
              <div className="onvif-command-field onvif-command-field-full onvif-command-scheme-field onvif-command-ffmpeg-transport">
                <div className="onvif-command-label-row">
                  <span
                    className="onvif-command-label-text"
                    id={onvifSnapTransportFieldId}
                  >
                    {t('onvif.jpegRtspTransport')}
                  </span>
                  <span className="onvif-command-label-hint">
                    {t('onvif.jpegFfmpegBadge')}
                  </span>
                </div>
                <div
                  aria-labelledby={onvifSnapTransportFieldId}
                  className="segmented-control onvif-command-scheme-seg onvif-command-ffmpeg-transport-seg"
                  role="group"
                >
                  {(['tcp', 'udp'] as const).map((value) => (
                    <button
                      className={
                        onvifSnapTransport === value
                          ? 'segmented-active'
                          : 'secondary'
                      }
                      key={value}
                      onClick={() => {
                        setOnvifSnapTransport(value);
                      }}
                      type="button"
                    >
                      {value.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
              <button
                aria-busy={onvifSnapLoading}
                className="secondary onvif-command-send"
                disabled={onvifSnapDisabled}
                onClick={() => {
                  void handleOnvifRtspSnapshot();
                }}
                type="button"
              >
                {onvifSnapLoading ? (
                  <>
                    <span className="onvif-command-spinner" aria-hidden />
                    {t('onvif.capturing')}
                  </>
                ) : (
                  <>
                    <ImageIcon aria-hidden size={17} strokeWidth={2} />
                    {t('onvif.captureOnvif')}
                  </>
                )}
              </button>
              {onvifSnapError !== null && (
                <div className="onvif-command-error" role="alert">
                  {onvifSnapError}
                </div>
              )}
              {onvifSnapImageUrl !== null && (
                <div className="rtsp-snapshot-preview rtsp-snapshot-preview--has-image onvif-command-snap-wrap">
                  <img
                    alt={t('onvif.jpegAlt')}
                    className="rtsp-snapshot-image"
                    src={onvifSnapImageUrl}
                  />
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="onvif-command-toolbar">
          <button
            aria-busy={loading}
            className="primary onvif-command-send"
            disabled={sendDisabled}
            onClick={() => {
              void handleSend();
            }}
            type="button"
          >
            {loading ? (
              <>
                <span className="onvif-command-spinner" aria-hidden />
                {t('onvif.sending')}
              </>
            ) : (
              <>
                <RadioTower aria-hidden size={17} strokeWidth={2} />
                {t('onvif.sendCommand')}
              </>
            )}
          </button>
          {canSuggestRtsp && onRtspStreamSuggested !== undefined && (
            <button
              className="secondary onvif-command-send"
              onClick={suggestRtspFromParsed}
              type="button"
            >
              {t('onvif.useStreamForRtsp')}
            </button>
          )}
        </div>

        {loading && <div aria-hidden className="onvif-command-progress" />}

        <div aria-live="polite" className="onvif-command-live">
          {error !== null && (
            <div className="onvif-command-error" role="alert">
              {error}
            </div>
          )}
        </div>

        {result !== null && (
          <div className="onvif-command-response">
            <div className="onvif-command-response-head">
              <h4 className="onvif-command-response-title" id={responseTitleId}>
                {t('onvif.responseTitle')}
              </h4>
              {hasOnvifResponseBody && (
                <CopyButton
                  className="secondary onvif-command-copy"
                  label={t('onvif.copyBody')}
                  size={16}
                  text={result.body}
                />
              )}
            </div>
            {lastResultCommand !== null && lastResultCommand !== command && (
              <div className="onvif-command-response-stale" role="status">
                <Trans
                  components={{
                    cmd: <span className="onvif-command-response-stale-cmd" />,
                  }}
                  i18nKey="onvif.staleResponse"
                  values={{
                    command: onvifCommandLabel(lastResultCommand, t),
                  }}
                />
              </div>
            )}
            <div className="onvif-command-response-meta">
              <span
                className={`onvif-command-status onvif-command-status--${statusTone}`}
              >
                HTTP {result.status_code}
              </span>
              {result.content_type !== '' && (
                <span
                  className="onvif-command-response-ct"
                  title={result.content_type}
                >
                  {result.content_type}
                </span>
              )}
              {result.truncated && (
                <span className="onvif-command-response-trunc">
                  {t('onvif.truncated')}
                </span>
              )}
            </div>
            {((result.parse_warnings !== undefined &&
              result.parse_warnings.length > 0) ||
              (result.parsed !== undefined &&
                Object.keys(result.parsed).length > 0)) && (
              <div className="onvif-command-parsed-panel">
                <div className="onvif-command-parsed-head">
                  {t('onvif.parsed')}
                </div>
                {result.parse_warnings !== undefined &&
                  result.parse_warnings.length > 0 && (
                    <p className="onvif-command-parse-warn" role="status">
                      {result.parse_warnings.join(' · ')}
                    </p>
                  )}
                {result.parsed !== undefined &&
                  Object.keys(result.parsed).length > 0 && (
                    <pre className="onvif-command-response-parsed">
                      {JSON.stringify(result.parsed, null, 2)}
                    </pre>
                  )}
              </div>
            )}
            {hasOnvifResponseBody && (
              <div
                aria-labelledby={responseTitleId}
                className="onvif-command-response-shell"
                role="region"
              >
                <pre className="onvif-command-response-body">{result.body}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
