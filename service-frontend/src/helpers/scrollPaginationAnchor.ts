export function scrollPaginationAnchor(root?: ParentNode | null) {
  const scope = root ?? document;
  const el = scope.querySelector<HTMLElement>('.pagination-scroll-anchor');
  el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
