import type { TFunction } from 'i18next';
import { z } from 'zod';

export const createLoginSchema = (t: TFunction) =>
  z.object({
    username: z.string().trim().min(1, t('auth.validation.usernameRequired')),
    password: z.string().min(1, t('auth.validation.passwordRequired')),
  });

export type LoginFormValues = z.infer<ReturnType<typeof createLoginSchema>>;
