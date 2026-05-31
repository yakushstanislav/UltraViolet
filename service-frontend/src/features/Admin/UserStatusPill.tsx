import { CheckCircle2, MinusCircle } from 'lucide-react';

type UserStatusPillProps = {
  active: boolean;
  disabled: boolean;
  ariaLabel: string;
  activeLabel: string;
  disabledLabel: string;
  onClick: () => void;
};

export function UserStatusPill({
  active,
  disabled,
  ariaLabel,
  activeLabel,
  disabledLabel,
  onClick,
}: UserStatusPillProps) {
  return (
    <button
      aria-label={ariaLabel}
      aria-pressed={active}
      className={`status user-status-pill ${
        active ? 'user-status-pill-active' : 'user-status-pill-disabled'
      }`}
      disabled={disabled}
      onClick={onClick}
      type="button"
    >
      {active ? (
        <CheckCircle2 aria-hidden size={12} />
      ) : (
        <MinusCircle aria-hidden size={12} />
      )}
      {active ? activeLabel : disabledLabel}
    </button>
  );
}
