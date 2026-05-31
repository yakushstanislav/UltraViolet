import { useSwipeGesture } from '@/hooks/useSwipeGesture';

type SheetDragHandleProps = {
  onDismiss: () => void;
  disabled?: boolean;
};

export function SheetDragHandle({ onDismiss, disabled }: SheetDragHandleProps) {
  const handlers = useSwipeGesture({
    onSwipeDown: onDismiss,
    threshold: 120,
    disabled,
  });

  return (
    <div
      aria-hidden
      className="uv-sheet-grip"
      {...handlers}
    >
      <div className="uv-dialog__handle" />
    </div>
  );
}
