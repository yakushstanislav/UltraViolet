import { useEffect } from 'react';

export type ShortcutHandler = (event: KeyboardEvent) => void;

export type ShortcutOptions = {
  meta?: boolean;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  /** Allow the shortcut to fire while an editable element is focused. */
  allowInInputs?: boolean;
};

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  if (target.isContentEditable) {
    return true;
  }

  const tag = target.tagName;

  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
}

export function useGlobalShortcut(
  key: string,
  handler: ShortcutHandler,
  options: ShortcutOptions = { meta: true, ctrl: true }
): void {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const metaOk = options.meta ? event.metaKey : !event.metaKey;
      const ctrlOk = options.ctrl ? event.ctrlKey : !event.ctrlKey;
      const matchesModifier =
        options.meta || options.ctrl
          ? event.metaKey || event.ctrlKey
          : metaOk && ctrlOk;

      if (!matchesModifier) {
        return;
      }

      if (options.shift !== undefined && options.shift !== event.shiftKey) {
        return;
      }

      if (options.alt !== undefined && options.alt !== event.altKey) {
        return;
      }

      if (event.key.toLowerCase() !== key.toLowerCase()) {
        return;
      }

      if (
        !options.allowInInputs &&
        !options.meta &&
        !options.ctrl &&
        isEditableTarget(event.target)
      ) {
        return;
      }

      handler(event);
    };

    window.addEventListener('keydown', onKey);

    return () => window.removeEventListener('keydown', onKey);
  }, [
    key,
    handler,
    options.meta,
    options.ctrl,
    options.shift,
    options.alt,
    options.allowInInputs,
  ]);
}
