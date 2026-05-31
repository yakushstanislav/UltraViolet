import * as Dialog from '@radix-ui/react-dialog';
import { Crosshair, X } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { DialogSheetContent } from '@components/DialogSheetContent';
import { isIPv4 } from '@helpers/inetAddr';
import { showActionError, showActionSuccess } from '@helpers/uiError';
import { useAppDispatch, useAppSelector } from '@store/store';
import type { CreateScanRequest, ScanMode, SlowProfile } from '@/types/scans';

import { submitScan } from '../Scans/scansActions';

const MODE_OPTIONS: Array<{
  value: ScanMode;
  labelKey: string;
  ipv4Only: boolean;
}> = [
  { value: 'slow', labelKey: 'hostPage.deepScanModeSlow', ipv4Only: false },
  {
    value: 'masscan',
    labelKey: 'hostPage.deepScanModeMasscan',
    ipv4Only: true,
  },
  { value: 'zmap', labelKey: 'hostPage.deepScanModeZmap', ipv4Only: true },
];

const SLOW_PROFILE_OPTIONS: Array<{ value: SlowProfile; labelKey: string }> = [
  { value: 'stealth', labelKey: 'hostPage.deepScanProfileStealth' },
  { value: 'balanced', labelKey: 'hostPage.deepScanProfileBalanced' },
  { value: 'aggressive', labelKey: 'hostPage.deepScanProfileAggressive' },
];

type Props = {
  ip: string;
};

function ipv4SubnetCidr(ip: string): string | null {
  const parts = ip.split('.');

  if (parts.length !== 4) {
    return null;
  }

  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

export function HostDeepScanButton({ ip }: Props) {
  const { t } = useTranslation();
  const dispatch = useAppDispatch();
  const role = useAppSelector((state) => state.auth.role);
  const canCreate = role === 'operator' || role === 'admin';
  const ipv4 = isIPv4(ip);

  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<ScanMode>('slow');
  const [slowProfile, setSlowProfile] = useState<SlowProfile>('balanced');
  const [scanSubnet, setScanSubnet] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  if (!canCreate) {
    return null;
  }

  const effectiveMode: ScanMode =
    !ipv4 && (mode === 'masscan' || mode === 'zmap') ? 'slow' : mode;
  const subnetPreview = ipv4 ? ipv4SubnetCidr(ip) : null;
  const targetPreview = scanSubnet
    ? (subnetPreview ?? `${ip} /64`)
    : `${ip}/32`;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();

    const payload: CreateScanRequest = {
      name: `Deep scan ${ip}${scanSubnet ? ' subnet' : ''}`,
      target: ip,
      scan_subnet: scanSubnet,
      mode: effectiveMode,
      target_strategy: 'sequential',
      ports_expr: [{ from: 1, to: 65535 }],
    };

    if (effectiveMode === 'slow') {
      payload.slow_profile = slowProfile;
    }

    setSubmitting(true);

    try {
      const result = await dispatch(submitScan(payload)).unwrap();
      const queuedId = result.scan_ids[0];

      showActionSuccess('hostPage.toastDeepScanQueued', {
        id: queuedId ?? 0,
      });

      setOpen(false);
    } catch (err: unknown) {
      showActionError(err, 'hostPage.toastDeepScanFailed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog.Root onOpenChange={setOpen} open={open}>
      <Dialog.Trigger asChild>
        <button className="secondary" type="button">
          <Crosshair aria-hidden size={14} />
          {t('hostPage.deepScan')}
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogSheetContent
          className="host-deep-scan-dialog"
          onDismiss={() => setOpen(false)}
        >
          <Dialog.Title>
            {t('hostPage.deepScanDialogTitle', { ip })}
          </Dialog.Title>
          <Dialog.Description className="host-deep-scan-description">
            {t('hostPage.deepScanDialogDescription')}
          </Dialog.Description>
          <form onSubmit={handleSubmit}>
            <div className="scan-field-group">
              <span className="scan-field-label">
                {t('hostPage.deepScanEngineLabel')}
              </span>
              <div
                aria-label={t('hostPage.deepScanEngineLabel')}
                className="scan-segmented host-deep-scan-segmented"
                role="radiogroup"
              >
                {MODE_OPTIONS.map((opt) => {
                  const disabled = opt.ipv4Only && !ipv4;

                  return (
                    <label
                      className={
                        disabled
                          ? 'scan-segmented-option is-disabled'
                          : 'scan-segmented-option'
                      }
                      key={opt.value}
                      title={
                        disabled ? t('hostPage.deepScanIPv4Only') : undefined
                      }
                    >
                      <input
                        checked={mode === opt.value}
                        disabled={disabled}
                        name="deep-scan-mode"
                        onChange={() => setMode(opt.value)}
                        type="radio"
                        value={opt.value}
                      />
                      <span>{t(opt.labelKey)}</span>
                    </label>
                  );
                })}
              </div>
              {!ipv4 && (
                <p className="host-deep-scan-hint">
                  {t('hostPage.deepScanIPv4OnlyHint')}
                </p>
              )}
            </div>
            {effectiveMode === 'slow' && (
              <div className="scan-field-group">
                <span className="scan-field-label">
                  {t('hostPage.deepScanProfileLabel')}
                </span>
                <div
                  aria-label={t('hostPage.deepScanProfileLabel')}
                  className="scan-segmented host-deep-scan-segmented"
                  role="radiogroup"
                >
                  {SLOW_PROFILE_OPTIONS.map((opt) => (
                    <label className="scan-segmented-option" key={opt.value}>
                      <input
                        checked={slowProfile === opt.value}
                        name="deep-scan-profile"
                        onChange={() => setSlowProfile(opt.value)}
                        type="radio"
                        value={opt.value}
                      />
                      <span>{t(opt.labelKey)}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}
            <label className="host-deep-scan-subnet">
              <input
                checked={scanSubnet}
                onChange={(event) => setScanSubnet(event.target.checked)}
                type="checkbox"
              />
              <span className="host-deep-scan-subnet-body">
                <span className="host-deep-scan-subnet-title">
                  {ipv4
                    ? t('hostPage.deepScanScanSubnet')
                    : t('hostPage.deepScanScanSubnetV6')}
                </span>
                <span className="host-deep-scan-subnet-meta">
                  {t('hostPage.deepScanTargetMeta', {
                    target: targetPreview,
                  })}
                </span>
              </span>
            </label>
            <div className="dialog-actions">
              <Dialog.Close asChild>
                <button className="secondary" type="button">
                  <X aria-hidden size={16} />
                  {t('common.cancel')}
                </button>
              </Dialog.Close>
              <button disabled={submitting} type="submit">
                <Crosshair aria-hidden size={14} />
                {t('hostPage.deepScanSubmit')}
              </button>
            </div>
          </form>
        </DialogSheetContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
