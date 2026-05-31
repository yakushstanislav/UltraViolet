import { type KeyboardEvent, type ReactNode } from 'react';

import { SkeletonBar } from './Skeleton';

export type UvCardRowId = string | number;

export type UvCardContext = {
  isActive: boolean;
  isSelected: boolean;
  onActivate: () => void;
  selectionInput: ReactNode;
};

type UvCardListProps<T, ID extends UvCardRowId> = {
  rows: T[];
  getRowId: (row: T) => ID;
  renderCard: (row: T, ctx: UvCardContext) => ReactNode;
  loading?: boolean;
  loadingCount?: number;
  empty?: ReactNode;
  className?: string;
  onRowActivate?: (row: T) => void;
  activeId?: ID | null;
  selectable?: boolean;
  selectedIds?: Set<ID>;
  onToggleSelect?: (id: ID) => void;
  rowSelectAriaLabel?: (row: T) => string;
  cardClassName?: (row: T, isActive: boolean) => string | undefined;
};

export function UvCardList<T, ID extends UvCardRowId>({
  rows,
  getRowId,
  renderCard,
  loading = false,
  loadingCount = 4,
  empty,
  className,
  onRowActivate,
  activeId = null,
  selectable = false,
  selectedIds,
  onToggleSelect,
  rowSelectAriaLabel,
  cardClassName,
}: UvCardListProps<T, ID>) {
  if (loading && rows.length === 0) {
    return (
      <ul className={`uv-card-list${className ? ' ' + className : ''}`}>
        {Array.from({ length: loadingCount }, (_, idx) => (
          <li className="uv-card uv-card--skeleton" key={`skel-${idx}`}>
            <SkeletonBar size="long" />
            <SkeletonBar size="mid" />
            <SkeletonBar size="short" />
          </li>
        ))}
      </ul>
    );
  }

  if (!loading && rows.length === 0) {
    return <div className="uv-card-list__empty">{empty}</div>;
  }

  return (
    <ul className={`uv-card-list${className ? ' ' + className : ''}`}>
      {rows.map((row) => {
        const rowId = getRowId(row);
        const isActive = activeId !== null && activeId === rowId;
        const isSelected =
          selectable && selectedIds ? selectedIds.has(rowId) : false;
        const activate = () => onRowActivate?.(row);

        const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
          if (!onRowActivate) {
            return;
          }

          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            activate();
          }
        };

        const selectionInput = selectable ? (
          <input
            aria-label={rowSelectAriaLabel?.(row) ?? `Select row ${rowId}`}
            checked={isSelected}
            className="uv-card__select"
            onChange={() => onToggleSelect?.(rowId)}
            onClick={(event) => event.stopPropagation()}
            type="checkbox"
          />
        ) : null;

        const customClass = cardClassName?.(row, isActive);
        const classes = [
          'uv-card',
          isActive ? 'uv-card--active' : '',
          isSelected ? 'uv-card--selected' : '',
          onRowActivate ? 'uv-card--clickable' : '',
          customClass ?? '',
        ]
          .filter(Boolean)
          .join(' ');

        return (
          <li className="uv-card-list__item" key={rowId}>
            <div
              className={classes}
              onClick={onRowActivate ? activate : undefined}
              onKeyDown={onRowActivate ? handleKeyDown : undefined}
              role={onRowActivate ? 'button' : undefined}
              tabIndex={onRowActivate ? 0 : undefined}
            >
              {renderCard(row, {
                isActive,
                isSelected,
                onActivate: activate,
                selectionInput,
              })}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
