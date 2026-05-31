import createGlobe, { type Marker } from 'cobe';
import { useEffect, useRef } from 'react';

import { cobeGlobePreset } from '@helpers/cobeGlobePresets';
import {
  defaultAccentTriplet,
  readCssColorTriplet,
} from '@helpers/themeColors';

export type CobeGlobeFocus = {
  lat: number;
  lng: number;
};

export type UseCobeGlobeOptions = {
  markers: Marker[];
  theme: 'light' | 'dark';
  interactive?: boolean;
  mapSamples?: number;
  autoRotate?: boolean;
  focusLocation?: CobeGlobeFocus | null;
};

const autoRotateSpeed = 0.0025;
const dragSensitivity = 0.004;
const focusLerp = 0.08;

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }

  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function locationToAngles(lat: number, lng: number): { phi: number; theta: number } {
  return {
    phi: Math.PI + (lng * Math.PI) / 180,
    theta: 0.28 - (lat * Math.PI) / 360,
  };
}

function shortestAngleDelta(from: number, to: number): number {
  let delta = to - from;

  while (delta > Math.PI) {
    delta -= Math.PI * 2;
  }

  while (delta < -Math.PI) {
    delta += Math.PI * 2;
  }

  return delta;
}

export function useCobeGlobe({
  markers,
  theme,
  interactive = true,
  mapSamples,
  autoRotate = true,
  focusLocation = null,
}: UseCobeGlobeOptions) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const markersRef = useRef(markers);
  const phiRef = useRef(0);
  const thetaRef = useRef(0.28);
  const draggingRef = useRef(false);
  const pointerIdRef = useRef<number | null>(null);
  const lastPointerRef = useRef<{ x: number; y: number } | null>(null);
  const velocityRef = useRef({ phi: 0, theta: 0 });
  const focusRef = useRef(focusLocation);

  useEffect(() => {
    markersRef.current = markers;
  }, [markers]);

  useEffect(() => {
    focusRef.current = focusLocation;
  }, [focusLocation]);

  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap) {
      return;
    }

    const canvas = document.createElement('canvas');
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.display = 'block';
    wrap.replaceChildren(canvas);

    const isDark = theme === 'dark';
    const preset = cobeGlobePreset(theme);
    const markerColor = readCssColorTriplet(
      isDark ? '--accent' : '--primary',
      defaultAccentTriplet(theme)
    );
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const reducedMotion = prefersReducedMotion();
    const allowAutoRotate = autoRotate && !reducedMotion;

    const measure = () => {
      const r = wrap.getBoundingClientRect();
      const w = Math.max(120, Math.floor(r.width));
      const h = Math.max(120, Math.floor(r.height));

      return { w, h };
    };

    const { w, h } = measure();

    let globe: ReturnType<typeof createGlobe>;
    try {
      globe = createGlobe(canvas, {
        devicePixelRatio: dpr,
        width: w * dpr,
        height: h * dpr,
        phi: phiRef.current,
        theta: thetaRef.current,
        dark: isDark ? 1 : 0,
        diffuse: preset.diffuse,
        mapSamples: mapSamples ?? preset.mapSamples,
        mapBrightness: preset.mapBrightness,
        mapBaseBrightness: preset.mapBaseBrightness,
        baseColor: preset.baseColor,
        markerColor,
        glowColor: preset.glowColor,
        markers: markersRef.current,
      });
    } catch (error) {
      console.error('useCobeGlobe: createGlobe failed', error);
      wrap.replaceChildren();

      return;
    }

    let raf = 0;

    const tick = () => {
      const focus = focusRef.current;

      if (focus) {
        const target = locationToAngles(focus.lat, focus.lng);
        const dPhi = shortestAngleDelta(phiRef.current, target.phi);
        const dTheta = target.theta - thetaRef.current;

        if (Math.abs(dPhi) < 0.002 && Math.abs(dTheta) < 0.002) {
          phiRef.current = target.phi;
          thetaRef.current = target.theta;
          velocityRef.current = { phi: 0, theta: 0 };
        } else {
          phiRef.current += dPhi * focusLerp;
          thetaRef.current += dTheta * focusLerp;
        }
      } else if (!draggingRef.current) {
        if (Math.abs(velocityRef.current.phi) > 0.0001) {
          phiRef.current += velocityRef.current.phi;
          velocityRef.current.phi *= 0.92;
        } else {
          velocityRef.current.phi = 0;
        }

        if (Math.abs(velocityRef.current.theta) > 0.0001) {
          thetaRef.current += velocityRef.current.theta;
          velocityRef.current.theta *= 0.92;
        } else {
          velocityRef.current.theta = 0;
        }

        if (allowAutoRotate && velocityRef.current.phi === 0) {
          phiRef.current += autoRotateSpeed;
        }
      }

      thetaRef.current = Math.max(-0.5, Math.min(1.1, thetaRef.current));

      globe.update({
        phi: phiRef.current,
        theta: thetaRef.current,
        markers: markersRef.current,
      });

      raf = requestAnimationFrame(tick);
    };

    tick();

    const onPointerDown = (event: PointerEvent) => {
      if (!interactive) {
        return;
      }

      draggingRef.current = true;
      pointerIdRef.current = event.pointerId;
      lastPointerRef.current = { x: event.clientX, y: event.clientY };
      velocityRef.current = { phi: 0, theta: 0 };
      wrap.setPointerCapture(event.pointerId);
      wrap.classList.add('dashboard-globe-canvas-wrap--dragging');
    };

    const onPointerMove = (event: PointerEvent) => {
      if (!interactive || !draggingRef.current || pointerIdRef.current !== event.pointerId) {
        return;
      }

      const last = lastPointerRef.current;
      if (!last) {
        return;
      }

      const dx = event.clientX - last.x;
      const dy = event.clientY - last.y;

      lastPointerRef.current = { x: event.clientX, y: event.clientY };

      phiRef.current += dx * dragSensitivity;
      thetaRef.current += dy * dragSensitivity;
      velocityRef.current = {
        phi: dx * dragSensitivity * 0.35,
        theta: dy * dragSensitivity * 0.35,
      };
    };

    const endDrag = (event: PointerEvent) => {
      if (pointerIdRef.current !== event.pointerId) {
        return;
      }

      draggingRef.current = false;
      pointerIdRef.current = null;
      lastPointerRef.current = null;

      if (wrap.hasPointerCapture(event.pointerId)) {
        wrap.releasePointerCapture(event.pointerId);
      }

      wrap.classList.remove('dashboard-globe-canvas-wrap--dragging');
    };

    if (interactive) {
      wrap.addEventListener('pointerdown', onPointerDown);
      wrap.addEventListener('pointermove', onPointerMove);
      wrap.addEventListener('pointerup', endDrag);
      wrap.addEventListener('pointercancel', endDrag);
    }

    const ro = new ResizeObserver(() => {
      const { w: nw, h: nh } = measure();
      globe.update({
        width: nw * dpr,
        height: nh * dpr,
        markers: markersRef.current,
      });
    });

    ro.observe(wrap);

    const rafRemeasure = requestAnimationFrame(() => {
      const { w: nw, h: nh } = measure();
      globe.update({
        width: nw * dpr,
        height: nh * dpr,
        markers: markersRef.current,
      });
    });

    return () => {
      cancelAnimationFrame(rafRemeasure);
      cancelAnimationFrame(raf);
      ro.disconnect();

      if (interactive) {
        wrap.removeEventListener('pointerdown', onPointerDown);
        wrap.removeEventListener('pointermove', onPointerMove);
        wrap.removeEventListener('pointerup', endDrag);
        wrap.removeEventListener('pointercancel', endDrag);
      }

      globe.destroy();
      wrap.replaceChildren();
      wrap.classList.remove('dashboard-globe-canvas-wrap--dragging');
    };
  }, [autoRotate, interactive, mapSamples, theme]);

  return { wrapRef };
}
