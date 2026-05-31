export type ScanStatusFilter =
  | 'all'
  | 'pending'
  | 'running'
  | 'paused'
  | 'done'
  | 'failed'
  | 'canceled';

export type ListSortKey = 'id' | 'created_at' | 'status';

export type ListOrder = 'asc' | 'desc';

const STATUS_VALUES: ReadonlyArray<Exclude<ScanStatusFilter, 'all'>> = [
  'pending',
  'running',
  'paused',
  'done',
  'failed',
  'canceled',
];

const SORT_VALUES: ReadonlyArray<ListSortKey> = ['id', 'created_at', 'status'];

const ORDER_VALUES: ReadonlyArray<ListOrder> = ['asc', 'desc'];

export function parseStatusFilter(value: string | null): ScanStatusFilter {
  if (value !== null && (STATUS_VALUES as readonly string[]).includes(value)) {
    return value as ScanStatusFilter;
  }

  return 'all';
}

export function parseListSort(value: string | null): ListSortKey | undefined {
  if (value !== null && (SORT_VALUES as readonly string[]).includes(value)) {
    return value as ListSortKey;
  }

  return undefined;
}

export function parseListOrder(value: string | null): ListOrder | undefined {
  if (value !== null && (ORDER_VALUES as readonly string[]).includes(value)) {
    return value as ListOrder;
  }

  return undefined;
}

export function defaultOrderForSort(column: ListSortKey): ListOrder {
  if (column === 'status') {
    return 'asc';
  }

  return 'desc';
}
