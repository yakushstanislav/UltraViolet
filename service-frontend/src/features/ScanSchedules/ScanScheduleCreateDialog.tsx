import * as Dialog from '@radix-ui/react-dialog';
import { Plus, X } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';

import { DialogSheetContent } from '@components/DialogSheetContent';
import { ScanCreateFormBody } from '@features/Scans/ScanCreateFormBody';
import { ScheduleIntervalSelect } from '@features/Scans/ScheduleIntervalSelect';
import { SCAN_CREATE_FORM_DEFAULTS } from '@features/Scans/scanFormDefaults';
import { scanFormValuesToScheduleRequest } from '@features/Scans/scanFormPayload';
import { useScanCreateForm } from '@features/Scans/useScanCreateForm';
import { useDemoMode } from '@/hooks/useDemoMode';
import { resolveScanCreateErrorMessage } from '@helpers/scanCreateApiError';
import { generateRandomScanName } from '@helpers/randomScanName';
import type { ScanFormValues } from '@schemas/scan';
import { createScanSchedule } from '@services/ScanScheduleAPI';

type ScanScheduleCreateDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: () => void;
};

export function ScanScheduleCreateDialog({
  open,
  onOpenChange,
  onCreated,
}: ScanScheduleCreateDialogProps) {
  const { t } = useTranslation();
  const demoMode = useDemoMode();
  const [intervalSeconds, setIntervalSeconds] = useState(3600);
  const scanForm = useScanCreateForm({ open });
  const { form, setScanDialogContentEl } = scanForm;

  const handleSubmit = async (values: ScanFormValues) => {
    try {
      await createScanSchedule(
        scanFormValuesToScheduleRequest(
          values,
          intervalSeconds,
          t('scanSchedules.unnamed')
        )
      );
      toast.success(t('scanSchedules.created'));
      onOpenChange(false);
      setIntervalSeconds(3600);
      form.reset({
        ...SCAN_CREATE_FORM_DEFAULTS,
        name: generateRandomScanName(),
      });
      onCreated?.();
    } catch (err) {
      toast.error(resolveScanCreateErrorMessage(err, t('common.createFailed')));
    }
  };

  return (
    <Dialog.Root onOpenChange={onOpenChange} open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogSheetContent
          onDismiss={() => onOpenChange(false)}
          ref={setScanDialogContentEl}
        >
          <Dialog.Title>{t('scanSchedules.dialogTitle')}</Dialog.Title>
          <form onSubmit={form.handleSubmit(handleSubmit)}>
            <ScanCreateFormBody scanForm={scanForm} />
            <div className="scan-form-section">
              <label className="search-field">
                <span className="search-field-label">
                  {t('scanSchedules.interval')}
                </span>
                <ScheduleIntervalSelect
                  onChange={setIntervalSeconds}
                  value={intervalSeconds}
                />
              </label>
            </div>
            <div className="dialog-actions">
              <Dialog.Close asChild>
                <button className="secondary" type="button">
                  <X aria-hidden size={16} />
                  {t('common.cancel')}
                </button>
              </Dialog.Close>
              <button disabled={demoMode} type="submit">
                <Plus aria-hidden size={16} />
                {t('common.create')}
              </button>
            </div>
          </form>
        </DialogSheetContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
