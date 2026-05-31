import { type ReactNode } from 'react';

import { SkeletonRow } from './Skeleton';
import type { SkeletonBarSize } from './Skeleton';

export type DataTableColumn<T> = {
  key: string;
  header: ReactNode;
  className?: string;
  cell?: (row: T) => ReactNode;
};

export type RowId = string | number;

type DataTableProps<T extends { id: RowId }> = {
  columns: DataTableColumn<T>[];
  rows: T[];
  loading?: boolean;
  loadingRowCount?: number;
  loadingCells?: SkeletonBarSize[];
  empty?: ReactNode;
  className?: string;
  minWidth?: number;
  selectable?: boolean;
  selectedIds?: Set<RowId>;
  onToggleSelect?: (id: RowId) => void;
  onToggleAll?: () => void;
  allSelected?: boolean;
  someSelected?: boolean;
  selectAllAriaLabel?: string;
  rowSelectAriaLabel?: (row: T) => string;
  onRowActivate?: (row: T) => void;
  activeId?: RowId | null;
  rowClassName?: (row: T, isActive: boolean) => string | undefined;
  renderRow?: (row: T, ctx: RenderRowContext) => ReactNode;
};

export type RenderRowContext = {
  isActive: boolean;
  isSelected: boolean;
  onActivate: () => void;
  selectionCell: ReactNode;
};

function defaultLoadingCells(count: number): SkeletonBarSize[] {
  const sizes: SkeletonBarSize[] = ['short', 'mid', 'long'];
  return Array.from({ length: count }, (_, i) => sizes[i % sizes.length]!);
}

export function DataTable<T extends { id: RowId }>({
  columns,
  rows,
  loading = false,
  loadingRowCount = 6,
  loadingCells,
  empty,
  className,
  minWidth,
  selectable = false,
  selectedIds,
  onToggleSelect,
  onToggleAll,
  allSelected = false,
  someSelected = false,
  selectAllAriaLabel,
  rowSelectAriaLabel,
  onRowActivate,
  activeId = null,
  rowClassName,
  renderRow,
}: DataTableProps<T>) {
  const totalCols = columns.length + (selectable ? 1 : 0);
  const cells =
    loadingCells ??
    defaultLoadingCells(selectable ? columns.length + 1 : columns.length);

  return (
    <div
      className={`table-wrap uv-table-wrap${className ? ' ' + className : ''}`}
    >
      <table
        className="uv-table"
        style={minWidth ? { minWidth: `${minWidth}px` } : undefined}
      >
        <thead>
          <tr>
            {selectable && (
              <th className="uv-table-select-col">
                <input
                  aria-label={selectAllAriaLabel ?? 'Select all rows'}
                  checked={allSelected}
                  onChange={() => onToggleAll?.()}
                  ref={(el) => {
                    if (el) {
                      el.indeterminate = someSelected && !allSelected;
                    }
                  }}
                  type="checkbox"
                />
              </th>
            )}
            {columns.map((col) => (
              <th
                className={col.className}
                key={col.key}
                scope="col"
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading &&
            Array.from({ length: loadingRowCount }, (_, idx) => (
              <SkeletonRow cells={cells} key={`uv-table-skel-${idx}`} />
            ))}

          {!loading &&
            rows.map((row) => {
              const isActive = activeId !== null && activeId === row.id;
              const isSelected =
                selectable && selectedIds ? selectedIds.has(row.id) : false;
              const activate = () => onRowActivate?.(row);
              const selectionCell = selectable ? (
                <td className="uv-table-select-col">
                  <input
                    aria-label={
                      rowSelectAriaLabel?.(row) ?? `Select row ${row.id}`
                    }
                    checked={isSelected}
                    onChange={() => onToggleSelect?.(row.id)}
                    onClick={(event) => event.stopPropagation()}
                    type="checkbox"
                  />
                </td>
              ) : null;

              if (renderRow) {
                return renderRow(row, {
                  isActive,
                  isSelected,
                  onActivate: activate,
                  selectionCell,
                });
              }

              const customClass = rowClassName?.(row, isActive);
              const rowClasses = [
                isActive ? 'row-active' : '',
                onRowActivate ? 'scan-row-clickable' : '',
                customClass ?? '',
              ]
                .filter(Boolean)
                .join(' ');

              return (
                <tr
                  className={rowClasses || undefined}
                  key={row.id}
                  onClick={onRowActivate ? activate : undefined}
                  onKeyDown={
                    onRowActivate
                      ? (event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            activate();
                          }
                        }
                      : undefined
                  }
                  role={onRowActivate ? 'button' : undefined}
                  tabIndex={onRowActivate ? 0 : undefined}
                >
                  {selectionCell}
                  {columns.map((col) => (
                    <td className={col.className} key={col.key}>
                      {col.cell ? col.cell(row) : null}
                    </td>
                  ))}
                </tr>
              );
            })}

          {!loading && rows.length === 0 && (
            <tr>
              <td className="table-empty-cell" colSpan={totalCols}>
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
