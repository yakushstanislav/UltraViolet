import {
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
  type RefObject,
} from 'react';

type PaginationBarDockProps = {
  alignRef?: RefObject<HTMLElement | null>;
  alignToScope?: boolean;
  children: ReactNode;
  className?: string;
};

function resolveAlignTarget(
  dock: HTMLElement,
  alignRef?: RefObject<HTMLElement | null>,
  alignToScope?: boolean,
): HTMLElement {
  if (alignRef?.current) {
    return alignRef.current;
  }

  const scope =
    dock.closest<HTMLElement>('.pagination-bar-scope') ?? dock.parentElement;

  if (alignToScope && scope) {
    return scope;
  }

  const previous = dock.previousElementSibling;

  if (
    previous instanceof HTMLElement &&
    previous.classList.contains('pagination-scroll-anchor')
  ) {
    return previous;
  }

  if (!scope) {
    return dock;
  }

  const anchor = scope.querySelector<HTMLElement>('.pagination-scroll-anchor');

  if (anchor) {
    return anchor;
  }

  return scope;
}

export function PaginationBarDock({
  alignRef,
  alignToScope,
  children,
  className,
}: PaginationBarDockProps) {
  const dockRef = useRef<HTMLDivElement>(null);
  const [shellStyle, setShellStyle] = useState<CSSProperties>({});

  useLayoutEffect(() => {
    const dock = dockRef.current;

    if (!dock) {
      return;
    }

    if (dock.closest('.scans-detail-delta-panel')) {
      setShellStyle({});

      return;
    }

    const sync = () => {
      const alignTarget = resolveAlignTarget(dock, alignRef, alignToScope);
      const rect = alignTarget.getBoundingClientRect();
      setShellStyle({
        left: `${rect.left}px`,
        width: `${rect.width}px`,
      });
    };

    sync();

    const alignTarget = resolveAlignTarget(dock, alignRef, alignToScope);
    const observer = new ResizeObserver(sync);
    observer.observe(alignTarget);

    const scope =
      dock.closest<HTMLElement>('.pagination-bar-scope') ?? alignTarget;
    observer.observe(scope);

    window.addEventListener('resize', sync);
    window.addEventListener('scroll', sync, { passive: true });

    return () => {
      observer.disconnect();
      window.removeEventListener('resize', sync);
      window.removeEventListener('scroll', sync);
    };
  }, [alignRef, alignToScope]);

  return (
    <div
      className={['pagination-bar-dock', className].filter(Boolean).join(' ')}
      ref={dockRef}
    >
      <div
        className={[
          'pagination-bar-fixed-shell',
          alignToScope ? 'pagination-bar-fixed-shell--scope' : null,
        ]
          .filter(Boolean)
          .join(' ')}
        style={shellStyle}
      >
        {children}
      </div>
    </div>
  );
}
