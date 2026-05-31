export type CobeGlobePreset = {
  diffuse: number;
  mapSamples: number;
  mapBrightness: number;
  mapBaseBrightness: number;
  baseColor: [number, number, number];
  glowColor: [number, number, number];
  theta: number;
};

export const COBE_GLOBE_SAMPLES_FULL = 10000;

export function cobeGlobePreset(theme: 'light' | 'dark'): CobeGlobePreset {
  if (theme === 'dark') {
    return {
      diffuse: 1.15,
      mapSamples: COBE_GLOBE_SAMPLES_FULL,
      mapBrightness: 5.5,
      mapBaseBrightness: 0.12,
      baseColor: [0.18, 0.2, 0.28],
      glowColor: [0.35, 0.45, 0.65],
      theta: 0.28,
    };
  }

  return {
    diffuse: 1.15,
    mapSamples: COBE_GLOBE_SAMPLES_FULL,
    mapBrightness: 6.5,
    mapBaseBrightness: 0,
    baseColor: [0.94, 0.95, 0.98],
    glowColor: [0.85, 0.88, 1],
    theta: 0.28,
  };
}
