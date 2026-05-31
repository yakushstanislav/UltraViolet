export type SkeletonBarSize = 'short' | 'mid' | 'long';

type SkeletonBarProps = {
  size: SkeletonBarSize;
};

export function SkeletonBar({ size }: SkeletonBarProps) {
  return <span className={`skeleton-bar skeleton-bar-${size}`} />;
}

type SkeletonRowProps = {
  cells: SkeletonBarSize[];
};

export function SkeletonRow({ cells }: SkeletonRowProps) {
  return (
    <tr className="table-skeleton-row">
      {cells.map((size, index) => (
        <td key={index}>
          <SkeletonBar size={size} />
        </td>
      ))}
    </tr>
  );
}
