type ProbabilityBarProps = {
  /** Value in 0..1 (or 0..100 if `percent`). */
  value: number;
  /** Set when value is already in 0..100. */
  percent?: boolean;
  /** Optional accessibility label. */
  ariaLabel?: string;
};

export function ProbabilityBar({ value, percent, ariaLabel }: ProbabilityBarProps) {
  const pct = clampPercent(percent === true ? value : value * 100);

  return (
    <div
      aria-label={ariaLabel}
      className="probability-bar"
      role={ariaLabel !== undefined ? 'meter' : undefined}
      style={{ '--p': `${pct}%` } as React.CSSProperties}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(pct)}
    >
      <span aria-hidden className="probability-bar-fill" />
    </div>
  );
}

function clampPercent(raw: number): number {
  if (!Number.isFinite(raw)) {
    return 0;
  }

  if (raw < 0) {
    return 0;
  }

  if (raw > 100) {
    return 100;
  }

  return raw;
}
