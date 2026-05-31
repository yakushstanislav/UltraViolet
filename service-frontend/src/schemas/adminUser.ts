import type { TFunction } from 'i18next';
import { z } from 'zod';

const userPasswordField = (t: TFunction) =>
  z
    .string()
    .min(1, t('adminUsers.validation.passwordRequired'))
    .min(8, t('adminUsers.validation.passwordTooShort'))
    .max(128, t('adminUsers.validation.passwordTooLong'));

export const createUserSchema = (t: TFunction) =>
  z.object({
    username: z
      .string()
      .min(1, t('adminUsers.validation.usernameRequired'))
      .max(128, t('adminUsers.validation.usernameTooLong')),
    password: userPasswordField(t),
    role: z.enum(['viewer', 'operator', 'admin']),
  });

export type CreateUserFormValues = z.infer<ReturnType<typeof createUserSchema>>;

export const resetPasswordSchema = (t: TFunction) =>
  z.object({
    password: userPasswordField(t),
  });

export type ResetPasswordFormValues = z.infer<
  ReturnType<typeof resetPasswordSchema>
>;
