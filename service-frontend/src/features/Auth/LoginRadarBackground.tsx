import { useEffect, useRef } from 'react';

import {
  defaultAccentTriplet,
  readCssColorTriplet,
  type RGBTriplet,
} from '@helpers/themeColors';
import { useTheme } from '@/theme/ThemeProvider';

type Hue = 'accent' | 'primary' | 'danger';

type Node = {
  angle: number;
  radiusFraction: number;
  size: number;
  hue: Hue;
  // phase offset for the slow danger blink (only used by danger nodes)
  blinkPhase: number;
  // last sweep revolution at which this node emitted a contact ripple
  lastPingRev: number;
};

type Pulse = {
  born: number;
};

type Contact = {
  x: number;
  y: number;
  born: number;
  color: RGBTriplet;
};

const SWEEP_PERIOD_MS = 26000;
const PULSE_INTERVAL_MS = 5000;
const PULSE_LIFE_MS = 5200;
const PULSE_MAX = 3;
const RING_COUNT = 4;
const CONTACT_LIFE_MS = 1200;
const CONTACT_MAX = 28;
const DANGER_RATIO = 0.16;
const TWO_PI = Math.PI * 2;

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }

  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function mulberry32(seed: number): () => number {
  let a = seed;

  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildNodes(count: number): Node[] {
  const random = mulberry32(0x5a17);
  const nodes: Node[] = [];

  for (let i = 0; i < count; i += 1) {
    const angle = random() * TWO_PI;
    const radiusFraction = 0.12 + random() * 0.92;
    const roll = random();

    let hue: Hue = 'primary';
    if (roll < DANGER_RATIO) {
      hue = 'danger';
    } else if (roll < DANGER_RATIO + (1 - DANGER_RATIO) / 2) {
      hue = 'accent';
    }

    nodes.push({
      angle,
      radiusFraction,
      size: 1.4 + random() * 2,
      hue,
      blinkPhase: random() * TWO_PI,
      lastPingRev: -1,
    });
  }

  return nodes;
}

function rgba(triplet: RGBTriplet, alpha: number): string {
  const r = Math.round(triplet[0] * 255);
  const g = Math.round(triplet[1] * 255);
  const b = Math.round(triplet[2] * 255);

  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export function LoginRadarBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const { theme } = useTheme();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      return;
    }

    const isDark = theme === 'dark';
    const accent = readCssColorTriplet('--accent', defaultAccentTriplet(theme));
    const primary = readCssColorTriplet('--primary', defaultAccentTriplet(theme));
    const danger = readCssColorTriplet(
      '--danger',
      isDark ? [0.984, 0.443, 0.522] : [0.863, 0.149, 0.149],
    );

    const intensity = isDark
      ? {
          ring: 0.06,
          pulse: 0.09,
          beam: 0.15,
          nodeBase: 0.16,
          nodeFlash: 0.5,
          core: 0.26,
          glow: 0.5,
        }
      : {
          ring: 0.09,
          pulse: 0.08,
          beam: 0.11,
          nodeBase: 0.18,
          nodeFlash: 0.42,
          core: 0.18,
          glow: 0.38,
        };

    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const reducedMotion = prefersReducedMotion();

    let width = 0;
    let height = 0;
    let centerX = 0;
    let centerY = 0;
    let maxRadius = 0;
    let nodeCount = 40;
    let nodes = buildNodes(nodeCount);

    // current per-node screen coords + brightness, recomputed each frame
    const nodeX = new Float64Array(nodeCount);
    const nodeY = new Float64Array(nodeCount);
    const nodeBright = new Float64Array(nodeCount);

    let coordBuffers = { x: nodeX, y: nodeY, b: nodeBright };

    const rebuild = (count: number) => {
      nodeCount = count;
      nodes = buildNodes(count);
      coordBuffers = {
        x: new Float64Array(count),
        y: new Float64Array(count),
        b: new Float64Array(count),
      };
    };

    const measure = () => {
      const rect = canvas.getBoundingClientRect();
      width = Math.max(1, Math.floor(rect.width));
      height = Math.max(1, Math.floor(rect.height));

      const nextCount = width < 520 ? 24 : 40;
      if (nextCount !== nodeCount) {
        rebuild(nextCount);
      }

      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      centerX = width / 2;
      centerY = height / 2;
      maxRadius = Math.hypot(width, height) / 2 + 40;
    };

    const colorFor = (hue: Hue) => {
      if (hue === 'danger') {
        return danger;
      }

      return hue === 'accent' ? accent : primary;
    };

    // Compute node screen positions and brightness for the current frame.
    // cumulativeSweep is the unwrapped beam angle (radians); null = static.
    const updateNodes = (cumulativeSweep: number | null, now: number) => {
      const { x, y, b } = coordBuffers;

      nodes.forEach((node, i) => {
        const radius = maxRadius * node.radiusFraction;
        const px = centerX + Math.cos(node.angle) * radius;
        const py = centerY + Math.sin(node.angle) * radius;

        x[i] = px;
        y[i] = py;

        const depthFade = 1 - 0.35 * node.radiusFraction;
        let brightness = intensity.nodeBase * depthFade;

        // gentle slow blink to flag danger ("problem found") nodes
        if (node.hue === 'danger') {
          const blink = cumulativeSweep === null
            ? 0.18
            : 0.18 + 0.18 * (0.5 + 0.5 * Math.sin(now / 900 + node.blinkPhase));
          brightness += blink;
        }

        if (cumulativeSweep !== null) {
          let phase = (cumulativeSweep - node.angle) % TWO_PI;
          if (phase < 0) {
            phase += TWO_PI;
          }

          const flash = Math.exp(-phase * 3.4) * intensity.nodeFlash;
          brightness += flash;

          // contact ripple on the rising edge, once per revolution
          const rev = Math.floor((cumulativeSweep - node.angle) / TWO_PI);
          if (phase < 0.12 && rev > node.lastPingRev) {
            node.lastPingRev = rev;
            contacts.push({ x: px, y: py, born: now, color: colorFor(node.hue) });

            if (contacts.length > CONTACT_MAX) {
              contacts.shift();
            }
          }
        }

        b[i] = Math.min(1, brightness);
      });
    };

    const drawRings = () => {
      ctx.lineWidth = 1;

      for (let i = 1; i <= RING_COUNT; i += 1) {
        const radius = (maxRadius * i) / RING_COUNT;
        const fade = 1 - 0.45 * (i / RING_COUNT);

        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, TWO_PI);
        ctx.strokeStyle = rgba(accent, intensity.ring * fade);
        ctx.stroke();
      }
    };

    const drawPulses = (now: number) => {
      for (const pulse of pulses) {
        const life = (now - pulse.born) / PULSE_LIFE_MS;
        if (life < 0 || life > 1) {
          continue;
        }

        // ease-out for a more organic deceleration
        const eased = 1 - (1 - life) * (1 - life);
        const radius = maxRadius * eased;
        const alpha = intensity.pulse * (1 - life);

        // soft bloom (wide, faint) under the crisp ring
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, TWO_PI);
        ctx.lineWidth = 4;
        ctx.strokeStyle = rgba(accent, alpha * 0.4 * intensity.glow);
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, TWO_PI);
        ctx.lineWidth = 1.4;
        ctx.strokeStyle = rgba(accent, alpha);
        ctx.stroke();
      }
    };

    const drawBeam = (sweepAngle: number) => {
      const gradient = ctx.createConicGradient(sweepAngle, centerX, centerY);

      gradient.addColorStop(0, rgba(accent, intensity.beam));
      gradient.addColorStop(0.06, rgba(accent, intensity.beam * 0.6));
      gradient.addColorStop(0.18, rgba(primary, intensity.beam * 0.12));
      gradient.addColorStop(0.32, rgba(primary, 0));
      gradient.addColorStop(1, rgba(primary, 0));

      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, maxRadius, 0, TWO_PI);
      ctx.closePath();
      ctx.fillStyle = gradient;
      ctx.fill();

      // soft leading edge (no glow — keeps the sweep readable but calm)
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(
        centerX + Math.cos(sweepAngle) * maxRadius,
        centerY + Math.sin(sweepAngle) * maxRadius,
      );
      ctx.lineWidth = 1.2;
      ctx.strokeStyle = rgba(accent, Math.min(1, intensity.beam * 0.9));
      ctx.stroke();
    };

    const drawCore = (now: number) => {
      const pulse = reducedMotion
        ? 0.5
        : 0.5 + 0.5 * Math.sin((now / 2200) * Math.PI);
      const coreRadius = 26 + pulse * 10;
      const coreAlpha = intensity.core * (0.7 + pulse * 0.3);

      const glow = ctx.createRadialGradient(
        centerX,
        centerY,
        0,
        centerX,
        centerY,
        coreRadius,
      );
      glow.addColorStop(0, rgba(accent, coreAlpha));
      glow.addColorStop(0.5, rgba(accent, coreAlpha * 0.4));
      glow.addColorStop(1, rgba(accent, 0));

      ctx.beginPath();
      ctx.arc(centerX, centerY, coreRadius, 0, TWO_PI);
      ctx.fillStyle = glow;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(centerX, centerY, 2.2, 0, TWO_PI);
      ctx.fillStyle = rgba(accent, Math.min(1, 0.8 * intensity.glow + 0.2));
      ctx.fill();
    };

    const drawContacts = (now: number) => {
      for (const contact of contacts) {
        const life = (now - contact.born) / CONTACT_LIFE_MS;
        if (life < 0 || life > 1) {
          continue;
        }

        const eased = 1 - (1 - life) * (1 - life);
        const radius = 3 + eased * 25;
        const alpha = (1 - life) * 0.85 * intensity.glow;

        ctx.beginPath();
        ctx.arc(contact.x, contact.y, radius, 0, TWO_PI);
        ctx.lineWidth = 1.5 * (1 - life) + 0.3;
        ctx.strokeStyle = rgba(contact.color, alpha);
        ctx.stroke();
      }
    };

    const drawNodes = () => {
      const { x, y, b } = coordBuffers;

      nodes.forEach((node, i) => {
        const color = colorFor(node.hue);
        const brightness = b[i] ?? 0;
        const px = x[i] ?? 0;
        const py = y[i] ?? 0;
        const isDanger = node.hue === 'danger';

        // soft bloom halo (a touch wider/brighter for danger nodes)
        const haloRadius = node.size * (isDanger ? 5 : 4) + brightness * 6;
        const haloAlpha =
          Math.min(0.6, brightness * (isDanger ? 0.85 : 0.7)) * intensity.glow;
        const halo = ctx.createRadialGradient(px, py, 0, px, py, haloRadius);
        halo.addColorStop(0, rgba(color, haloAlpha));
        halo.addColorStop(1, rgba(color, 0));

        ctx.beginPath();
        ctx.arc(px, py, haloRadius, 0, TWO_PI);
        ctx.fillStyle = halo;
        ctx.fill();

        // crisp core dot
        ctx.beginPath();
        ctx.arc(px, py, node.size + (isDanger ? 0.4 : 0), 0, TWO_PI);
        ctx.fillStyle = rgba(color, Math.min(1, brightness + 0.15));
        ctx.fill();
      });
    };

    const pulses: Pulse[] = [];
    const contacts: Contact[] = [];
    let lastPulseAt = 0;
    let raf = 0;
    const start = performance.now();

    const render = (now: number) => {
      ctx.clearRect(0, 0, width, height);

      if (now - lastPulseAt >= PULSE_INTERVAL_MS) {
        pulses.push({ born: now });
        lastPulseAt = now;

        if (pulses.length > PULSE_MAX) {
          pulses.shift();
        }
      }

      while (
        contacts.length > 0 &&
        now - (contacts[0]?.born ?? now) > CONTACT_LIFE_MS
      ) {
        contacts.shift();
      }

      const cumulativeSweep = ((now - start) / SWEEP_PERIOD_MS) * TWO_PI;
      const sweepAngle = cumulativeSweep % TWO_PI;

      updateNodes(cumulativeSweep, now);

      drawRings();
      drawPulses(now);
      drawBeam(sweepAngle);
      drawCore(now);
      drawContacts(now);
      drawNodes();

      raf = requestAnimationFrame(render);
    };

    const renderStatic = () => {
      ctx.clearRect(0, 0, width, height);

      updateNodes(null, 0);

      drawRings();
      drawBeam(-Math.PI / 4);
      drawCore(0);
      drawNodes();
    };

    measure();

    if (reducedMotion) {
      renderStatic();
    } else {
      raf = requestAnimationFrame(render);
    }

    const resizeObserver = new ResizeObserver(() => {
      measure();

      if (reducedMotion) {
        renderStatic();
      }
    });

    resizeObserver.observe(canvas);

    return () => {
      cancelAnimationFrame(raf);
      resizeObserver.disconnect();
    };
  }, [theme]);

  return <canvas ref={canvasRef} className="login-radar" aria-hidden="true" />;
}
