function copyViaTextarea(payload: string): boolean {
  const textarea = document.createElement('textarea');
  textarea.value = payload;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();

  try {
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    document.body.removeChild(textarea);
  }
}

/**
 * Copies `payload` to the clipboard. Falls back to a hidden textarea +
 * `document.execCommand('copy')` when the modern API is unavailable or fails.
 * `onSuccess` / `onError` run only after the outcome is known.
 */
export function copyTextToClipboard(
  payload: string,
  onSuccess?: () => void,
  onError?: () => void
): void {
  if (payload === '') {
    onError?.();

    return;
  }

  if (navigator.clipboard?.writeText) {
    void navigator.clipboard
      .writeText(payload)
      .then(() => {
        onSuccess?.();
      })
      .catch(() => {
        if (copyViaTextarea(payload)) {
          onSuccess?.();
        } else {
          onError?.();
        }
      });

    return;
  }

  if (copyViaTextarea(payload)) {
    onSuccess?.();
  } else {
    onError?.();
  }
}
