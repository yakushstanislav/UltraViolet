import { ChevronDown, ChevronUp } from 'lucide-react';

export type SortOrder = 'asc' | 'desc';

type SortableHeaderProps = {
  label: string;
  sortKey: string;
  activeSortKey: string;
  order: SortOrder;
  onSort: (sortKey: string) => void;
  ariaLabel: string;
  className?: string;
  /** Defaults to `table-sort-btn`; scans table uses `scans-table-sort-btn`. */
  sortButtonClassName?: string;
};

export function SortableHeader({
  label,
  sortKey,
  activeSortKey,
  order,
  onSort,
  ariaLabel,
  className,
  sortButtonClassName = 'table-sort-btn',
}: SortableHeaderProps) {
  const active = activeSortKey === sortKey;
  const ariaSort = active
    ? order === 'asc'
      ? 'ascending'
      : 'descending'
    : undefined;
  const sortBtnClass = active
    ? `${sortButtonClassName} ${sortButtonClassName}-active`
    : sortButtonClassName;

  return (
    <th aria-sort={ariaSort} className={className}>
      <button
        aria-label={ariaLabel}
        className={sortBtnClass}
        onClick={() => onSort(sortKey)}
        type="button"
      >
        {label}
        {active &&
          (order === 'asc' ? (
            <ChevronUp aria-hidden size={14} />
          ) : (
            <ChevronDown aria-hidden size={14} />
          ))}
      </button>
    </th>
  );
}
