import { toast } from 'sonner';

import i18n from '@i18n/i18n';

import { extractApiErrorMessage } from './apiError';

/**
 * Error UX conventions:
 *
 * - Inline `<div className="error">` — page/view load failures, session
 *   expiry on the current screen, and form validation messages tied to fields.
 *   Keep visible while the surrounding context is still relevant.
 *
 * - `showActionError` / `toast.error` — failures after a user action when focus
 *   or context has moved on (start/stop scan, CRUD on alerts/saved searches,
 *   CSV export). Do not duplicate the same message inline and in a toast.
 */
export function showActionError(err: unknown, fallbackKey: string): void {
  toast.error(extractApiErrorMessage(err, i18n.t(fallbackKey)));
}

export function showActionSuccess(
  messageKey: string,
  opts?: Record<string, string | number>
): void {
  toast.success(i18n.t(messageKey, opts));
}
