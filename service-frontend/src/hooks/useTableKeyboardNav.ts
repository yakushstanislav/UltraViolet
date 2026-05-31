import { useCallback, useEffect, useRef, useState } from 'react';

export type TableKeyboardNavOptions<TId extends string | number> = {
  rowIds: TId[];
  onActivate?: (id: TId) => void;
  onToggleSelect?: (id: TId) => void;
  enabled?: boolean;
};

export type TableKeyboardNavState<TId extends string | number> = {
  activeId: TId | null;
  activeIndex: number;
  setActiveId: (id: TId | null) => void;
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

export function useTableKeyboardNav<TId extends string | number>({
  rowIds,
  onActivate,
  onToggleSelect,
  enabled = true,
}: TableKeyboardNavOptions<TId>): TableKeyboardNavState<TId> {
  const [activeIndex, setActiveIndex] = useState<number>(-1);
  const rowIdsRef = useRef(rowIds);

  useEffect(() => {
    rowIdsRef.current = rowIds;

    if (rowIds.length === 0) {
      setActiveIndex(-1);
      return;
    }

    setActiveIndex((current) => {
      if (current < 0) {
        return -1;
      }

      if (current >= rowIds.length) {
        return rowIds.length - 1;
      }

      return current;
    });
  }, [rowIds]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    const onKey = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }

      if (isEditableTarget(event.target)) {
        return;
      }

      const ids = rowIdsRef.current;
      if (ids.length === 0) {
        return;
      }

      const key = event.key;

      if (key === 'j' || key === 'ArrowDown') {
        event.preventDefault();
        setActiveIndex((current) => Math.min(ids.length - 1, current + 1));
        return;
      }

      if (key === 'k' || key === 'ArrowUp') {
        event.preventDefault();
        setActiveIndex((current) => Math.max(0, current === -1 ? 0 : current - 1));
        return;
      }

      if (key === 'Enter') {
        const id = ids[activeIndex];
        if (id !== undefined && onActivate) {
          event.preventDefault();
          onActivate(id);
        }

        return;
      }

      if (key === 'x') {
        const id = ids[activeIndex];
        if (id !== undefined && onToggleSelect) {
          event.preventDefault();
          onToggleSelect(id);
        }
      }
    };

    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [enabled, activeIndex, onActivate, onToggleSelect]);

  const setActiveId = useCallback(
    (id: TId | null) => {
      if (id === null) {
        setActiveIndex(-1);
        return;
      }

      const idx = rowIdsRef.current.indexOf(id);
      if (idx >= 0) {
        setActiveIndex(idx);
      }
    },
    []
  );

  const activeId = activeIndex >= 0 ? (rowIds[activeIndex] ?? null) : null;

  return { activeId, activeIndex, setActiveId };
}
