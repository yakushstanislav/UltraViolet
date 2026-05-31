import i18n from '@i18n/i18n';

import { extractDomainErrorMessage } from '@helpers/apiError';

/** Stable `reason` values from user admin 400 responses (see service-api apireason). */
const USER_API_REASONS = [
  'user_username_invalid',
  'user_password_invalid',
  'user_role_invalid',
  'user_invalid_input',
] as const;

const USER_CONFLICT_REASONS = ['user_username_taken'] as const;

const USER_POLICY_REASONS = [
  'cannot_deactivate_self',
  'cannot_delete_self',
  'cannot_change_own_role',
  'last_admin_protected',
  'user_policy_violation',
] as const;

export function resolveAdminUserErrorMessage(
  error: unknown,
  fallbackKey: string
): string {
  const fallback = i18n.t(fallbackKey);

  const fromApi = extractDomainErrorMessage(error, {
    reasons: USER_API_REASONS,
    i18nPrefix: 'adminUsers.apiReasons',
    fallback: '',
  });
  if (fromApi !== '') {
    return fromApi;
  }

  const fromConflict = extractDomainErrorMessage(error, {
    reasons: USER_CONFLICT_REASONS,
    i18nPrefix: 'adminUsers.conflictReasons',
    fallback: '',
  });
  if (fromConflict !== '') {
    return fromConflict;
  }

  return extractDomainErrorMessage(error, {
    reasons: USER_POLICY_REASONS,
    i18nPrefix: 'adminUsers.policyReasons',
    fallback,
  });
}
