import { useTheme } from '@/theme/ThemeProvider';

type BrandMarkProps = {
  size?: number;
  className?: string;
  'aria-hidden'?: boolean;
};

const BARS_LIGHT = [
  { x: 2, h: 6, fill: '#7c3aed' },
  { x: 6, h: 10, fill: '#a855f7' },
  { x: 10, h: 14, fill: '#8b5cf6' },
  { x: 14, h: 18, fill: '#06b6d4' },
  { x: 18, h: 22, fill: '#22d3ee' },
] as const;

const BARS_DARK = [
  { x: 2, h: 6, fill: '#1e3a8a' },
  { x: 6, h: 10, fill: '#1d4ed8' },
  { x: 10, h: 14, fill: '#3b82f6' },
  { x: 14, h: 18, fill: '#0891b2' },
  { x: 18, h: 22, fill: '#67e8f9' },
] as const;

export function BrandMark({
  size = 28,
  className,
  'aria-hidden': ariaHidden = true,
}: BrandMarkProps) {
  const { theme } = useTheme();
  const bars = theme === 'dark' ? BARS_DARK : BARS_LIGHT;

  return (
    <svg
      aria-hidden={ariaHidden}
      className={className}
      fill="none"
      height={size}
      viewBox="0 0 24 24"
      width={size}
      xmlns="http://www.w3.org/2000/svg"
    >
      {bars.map((bar) => (
        <rect
          fill={bar.fill}
          height={bar.h}
          key={bar.x}
          rx={1}
          width={3}
          x={bar.x}
          y={23 - bar.h}
        />
      ))}
    </svg>
  );
}
