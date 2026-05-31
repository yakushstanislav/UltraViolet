import axios from 'axios';
import { useEffect, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';

import { postHostOnvifLabCredentialProbe } from '@services/HostAPI';
import type { ONVIFLabCredentialProbeResponse } from '@/types/hosts';

import { formatOnvifUserMessage } from './onvifHelpers';

type OnvifLabProbeProps = {
  hostIp: string;
  port: number;
  scheme: 'http' | 'https';
  devicePath: string;
  user: string;
  onMatched: (username: string, password: string) => void;
};

export function OnvifLabProbe({
  hostIp,
  port,
  scheme,
  devicePath,
  user,
  onMatched,
}: OnvifLabProbeProps) {
  const { t } = useTranslation();
  const [confirm, setConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [outcome, setOutcome] =
    useState<ONVIFLabCredentialProbeResponse | null>(null);

  useEffect(() => {
    setConfirm(false);
    setMessage(null);
    setOutcome(null);
  }, [hostIp, port]);

  const handleRun = async () => {
    if (!confirm) {
      return;
    }

    setLoading(true);
    setMessage(null);
    setOutcome(null);

    try {
      const data = await postHostOnvifLabCredentialProbe(hostIp, {
        port,
        scheme,
        transport: 'tcp',
        device_path: devicePath === '' ? undefined : devicePath,
        user: user === '' ? undefined : user,
      });
      setOutcome(data);

      if (data.matched) {
        onMatched(data.username, data.password);
        setMessage(t('onvif.labMatched', { attempts: data.attempts }));
      } else {
        setMessage(t('onvif.labNoMatch', { attempts: data.attempts }));
      }
    } catch (err) {
      if (axios.isAxiosError(err)) {
        const data = err.response?.data;
        if (
          data != null &&
          typeof data === 'object' &&
          !(data instanceof Blob)
        ) {
          const d = data as { error?: string; reason?: string };
          setMessage(formatOnvifUserMessage(t, d.reason ?? d.error));
        } else {
          setMessage(err.message);
        }
      } else {
        setMessage(formatOnvifUserMessage(t, undefined));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <details className="onvif-command-lab-details">
      <summary className="onvif-command-lab-summary">
        <span className="onvif-command-lab-summary-row">
          <span className="onvif-command-lab-summary-chevron" aria-hidden />
          <span className="onvif-command-lab-badge">
            {t('onvif.labBadge')}
          </span>
          <span className="onvif-command-lab-summary-title">
            {t('onvif.labTitle')}
          </span>
        </span>
      </summary>
      <div className="onvif-command-lab-body">
        <div className="onvif-command-lab-notice" role="note">
          <span className="onvif-command-callout-glow" aria-hidden />
          <div className="onvif-command-lab-notice-copy">
            <p className="onvif-command-lab-notice-lead">
              <Trans
                components={{ code: <code className="onvif-command-code" /> }}
                i18nKey="onvif.labLead"
              />
            </p>
            <ul className="onvif-command-lab-notice-list">
              <li>
                <Trans
                  components={{ code: <code className="onvif-command-code" /> }}
                  i18nKey="onvif.labBulletFile"
                />
              </li>
              <li>
                <Trans
                  components={{ code: <code className="onvif-command-code" /> }}
                  i18nKey="onvif.labBulletEnabled"
                />
              </li>
              <li>{t('onvif.labBulletUsername')}</li>
            </ul>
          </div>
        </div>
        <label className="onvif-command-checkbox-row onvif-command-lab-confirm">
          <input
            checked={confirm}
            onChange={(e) => {
              setConfirm(e.target.checked);
            }}
            type="checkbox"
          />
          <span className="onvif-command-checkbox-hint">
            {t('onvif.labConfirm')}
          </span>
        </label>
        <button
          aria-busy={loading}
          className="secondary onvif-command-send onvif-command-lab-run"
          disabled={!confirm || loading}
          onClick={() => {
            void handleRun();
          }}
          type="button"
        >
          {loading ? (
            <>
              <span className="onvif-command-spinner" aria-hidden />
              {t('onvif.labProbing')}
            </>
          ) : (
            t('onvif.labRun')
          )}
        </button>
        {message !== null && (
          <div
            className={
              outcome !== null && outcome.matched
                ? 'onvif-command-lab-result onvif-command-lab-result--ok'
                : 'onvif-command-lab-result'
            }
            role="status"
          >
            {message}
          </div>
        )}
      </div>
    </details>
  );
}
