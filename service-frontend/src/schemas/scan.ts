import type { TFunction } from 'i18next';
import { z } from 'zod';

import { getSynEngineIPv4TargetHint } from '@helpers/scanCreateHints';
import { describeScanTargetIssue } from '@helpers/scanTargetHint';

export const createScanSchema = (t: TFunction) => {
  const portRangeSchema = z
    .object({
      from: z.number().int().min(1).max(65535),
      to: z.number().int().min(1).max(65535),
    })
    .refine((value) => value.from <= value.to, {
      message: t('scans.validation.rangeOrder'),
      path: ['to'],
    });

  return z
    .object({
      name: z
        .string()
        .trim()
        .max(255, t('scans.validation.nameTooLong'))
        .optional(),
      target: z.string().trim(),
      scanSubnet: z.boolean(),
      mode: z.enum(['slow', 'masscan', 'zmap']),
      slowProfile: z.enum(['stealth', 'balanced', 'aggressive']),
      targetStrategy: z.enum(['sequential', 'random', 'country']),
      country: z.string().optional(),
      hostLimit: z
        .number()
        .int()
        .min(1, t('scans.validation.hostLimitMin'))
        .optional(),
      portsExpr: z.array(portRangeSchema).min(1),
    })
    .superRefine((data, ctx) => {
      if (data.targetStrategy === 'sequential') {
        if (!data.target || data.target.trim() === '') {
          ctx.addIssue({
            code: 'custom',
            message: t('scans.validation.targetRequiredSequential'),
            path: ['target'],
          });

          return;
        }

        const msg = describeScanTargetIssue(data.target, t);
        if (msg) {
          ctx.addIssue({
            code: 'custom',
            message: msg,
            path: ['target'],
          });
        }
      }

      if (data.targetStrategy === 'random') {
        if (!data.hostLimit || data.hostLimit < 1) {
          ctx.addIssue({
            code: 'custom',
            message: t('scans.validation.hostLimitRandom'),
            path: ['hostLimit'],
          });
        }
      }

      if (data.targetStrategy === 'country') {
        if (!data.country || data.country.trim() === '') {
          ctx.addIssue({
            code: 'custom',
            message: t('scans.validation.countryRequired'),
            path: ['country'],
          });
        } else if (!/^[A-Za-z]{2}$/.test(data.country.trim())) {
          ctx.addIssue({
            code: 'custom',
            message: t('scans.validation.countryInvalid'),
            path: ['country'],
          });
        }

        if (!data.hostLimit || data.hostLimit < 1) {
          ctx.addIssue({
            code: 'custom',
            message: t('scans.validation.hostLimitCountry'),
            path: ['hostLimit'],
          });
        }
      }

      const synMsg = getSynEngineIPv4TargetHint(
        data.mode,
        data.targetStrategy,
        data.target ?? '',
        t
      );

      if (synMsg) {
        ctx.addIssue({
          code: 'custom',
          message: synMsg,
          path: ['target'],
        });
      }
    });
};

export type ScanFormValues = z.infer<ReturnType<typeof createScanSchema>>;
