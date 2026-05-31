import { useEffect } from 'react';
import type { FieldErrors } from 'react-hook-form';

import { fieldErrorId } from '@helpers/formField';

function firstErrorPath(errors: FieldErrors): string | undefined {
  for (const key of Object.keys(errors)) {
    const value = errors[key];
    if (value === undefined) {
      continue;
    }

    if (typeof value === 'object' && value !== null && 'message' in value) {
      return key;
    }

    if (typeof value === 'object' && value !== null) {
      const nested = firstErrorPath(value as FieldErrors);
      if (nested !== undefined) {
        return `${key}.${nested}`;
      }
    }
  }

  return undefined;
}

export function useFocusFirstError(
  errors: FieldErrors,
  enabled: boolean
): void {
  useEffect(() => {
    if (!enabled) {
      return;
    }

    const path = firstErrorPath(errors);
    if (path === undefined) {
      return;
    }

    const root = path.split('.')[0] ?? path;
    const byErrorId = document.getElementById(fieldErrorId(root));
    const byName =
      document.querySelector<HTMLElement>(`[name="${root}"]`) ??
      document.querySelector<HTMLElement>(`[name="${path}"]`);
    const target = byName ?? byErrorId;

    if (target === null) {
      return;
    }

    if (target instanceof HTMLInputElement || target instanceof HTMLButtonElement) {
      target.focus({ preventScroll: true });
    }

    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, [enabled, errors]);
}
