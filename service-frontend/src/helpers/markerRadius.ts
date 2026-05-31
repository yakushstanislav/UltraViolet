export type ScaleRange = {
  min: number;
  max: number;
};

export const LEAFLET_RADIUS_RANGE: ScaleRange = { min: 6, max: 32 };
export const COBE_MARKER_RANGE: ScaleRange = { min: 0.035, max: 0.125 };

export function scaleByCount(
  count: number,
  maxCount: number,
  range: ScaleRange
): number {
  if (maxCount <= 0 || count <= 0) {
    return range.min;
  }

  const ratio = Math.min(1, count / maxCount);
  const scaled = range.min + (range.max - range.min) * Math.sqrt(ratio);

  return Math.max(range.min, Math.min(range.max, scaled));
}

export function leafletRadius(count: number, maxCount: number): number {
  return scaleByCount(count, maxCount, LEAFLET_RADIUS_RANGE);
}

export function cobeMarkerSize(count: number, maxCount: number): number {
  return scaleByCount(count, maxCount, COBE_MARKER_RANGE);
}
