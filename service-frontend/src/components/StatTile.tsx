import type { ReactNode } from 'react';

export type StatTileTone = 'default' | 'success' | 'warning' | 'danger' | 'muted';

type StatTileProps = {
  icon?: ReactNode;
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: StatTileTone;
  /** When set the tile becomes a button (filter affordance). */
  onClick?: () => void;
  active?: boolean;
};

const TONE_CLASS: Record<StatTileTone, string> = {
  default: '',
  success: 'stat-tile-icon-tone-success',
  warning: 'stat-tile-icon-tone-warning',
  danger: 'stat-tile-icon-tone-danger',
  muted: 'stat-tile-icon-tone-muted',
};

export function StatTile({
  icon,
  label,
  value,
  hint,
  tone = 'default',
  onClick,
  active = false,
}: StatTileProps) {
  const body = (
    <>
      {icon !== undefined && (
        <span aria-hidden className={`stat-tile-icon ${TONE_CLASS[tone]}`}>
          {icon}
        </span>
      )}
      <span className="stat-tile-body">
        <span className="stat-tile-label">{label}</span>
        <span className="stat-tile-value">{value}</span>
        {hint !== undefined && hint !== '' && (
          <span className="stat-tile-hint">{hint}</span>
        )}
      </span>
    </>
  );

  if (onClick !== undefined) {
    return (
      <button
        aria-pressed={active}
        className={active ? 'stat-tile stat-tile-active' : 'stat-tile'}
        onClick={onClick}
        type="button"
      >
        {body}
      </button>
    );
  }

  return <div className="stat-tile">{body}</div>;
}

type StatTileRowProps = {
  children: ReactNode;
};

export function StatTileRow({ children }: StatTileRowProps) {
  return <div className="stat-tile-row">{children}</div>;
}
