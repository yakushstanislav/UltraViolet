import { extractDomainErrorMessage } from '@helpers/apiError';

/** Stable `reason` values from 409 scan state-transition responses (see service-api apireason). */
const SCAN_CONFLICT_REASONS = [
  'scan_not_cancelable',
  'scan_not_pauseable',
  'scan_not_resumable',
  'scan_not_restartable',
] as const;

export function resolveScanConflictErrorMessage(
  error: unknown,
  fallback: string
): string {
  return extractDomainErrorMessage(error, {
    reasons: SCAN_CONFLICT_REASONS,
    i18nPrefix: 'scans.conflictReasons',
    fallback,
  });
}
