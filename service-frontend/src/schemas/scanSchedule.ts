import type { TFunction } from 'i18next';
import { z } from 'zod';

import { SCAN_SCHEDULE_INTERVAL_SECONDS } from '@features/Scans/scanScheduleIntervals';

import { createScanSchema } from './scan';

export const createScanScheduleSchema = (t: TFunction) =>
  createScanSchema(t).extend({
    interval_seconds: z
      .number()
      .refine(
        (value) =>
          (SCAN_SCHEDULE_INTERVAL_SECONDS as readonly number[]).includes(value),
        {
          message: t('scanSchedules.intervalInvalid'),
        }
      ),
  });

export type ScanScheduleFormValues = z.infer<
  ReturnType<typeof createScanScheduleSchema>
>;
