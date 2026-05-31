import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { isAbortError } from '@helpers/abortError';
import { getHostRiskHistory } from '@services/HostAPI';
import type { RiskHistoryPoint } from '@/types/risk';

type Range = '7d' | '30d' | '90d' | '365d';

const RANGES: { id: Range; days: number; labelKey: string }[] = [
  { id: '7d', days: 7, labelKey: 'risk.history.range7d' },
  { id: '30d', days: 30, labelKey: 'risk.history.range30d' },
  { id: '90d', days: 90, labelKey: 'risk.history.range90d' },
  { id: '365d', days: 365, labelKey: 'risk.history.range365d' },
];

const CHART_HEIGHT = 96;
const CHART_PADDING_X = 4;
const CHART_PADDING_TOP = 8;
const CHART_PADDING_BOTTOM = 4;

type HostRiskHistoryChartProps = {
  ip: string;
};

export function HostRiskHistoryChart({ ip }: HostRiskHistoryChartProps) {
  const { t, i18n } = useTranslation();
  const [range, setRange] = useState<Range>('30d');
  const [points, setPoints] = useState<RiskHistoryPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [width, setWidth] = useState(480);
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const days = useMemo(
    () => RANGES.find((r) => r.id === range)?.days ?? 30,
    [range],
  );

  useEffect(() => {
    const controller = new AbortController();

    setLoading(true);
    setError(null);

    getHostRiskHistory(ip, { days, limit: 1000 }, controller.signal)
      .then((response) => setPoints(response.points ?? []))
      .catch((err: unknown) => {
        if (isAbortError(err)) {
          return;
        }

        setError(t('common.loadFailed'));
      })
      .finally(() => setLoading(false));

    return () => controller.abort();
  }, [ip, days, t]);

  useEffect(() => {
    if (containerRef.current == null) {
      return;
    }

    const ro = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry != null) {
        setWidth(Math.max(160, Math.floor(entry.contentRect.width)));
      }
    });

    ro.observe(containerRef.current);

    return () => ro.disconnect();
  }, []);

  const geometry = useMemo(() => {
    if (points.length === 0) {
      return null;
    }

    const innerW = Math.max(20, width - CHART_PADDING_X * 2);
    const innerH = Math.max(20, CHART_HEIGHT - CHART_PADDING_TOP - CHART_PADDING_BOTTOM);
    const stepX =
      points.length > 1 ? innerW / (points.length - 1) : 0;

    const xy = points.map((point, idx) => {
      const x =
        points.length === 1
          ? CHART_PADDING_X + innerW / 2
          : CHART_PADDING_X + idx * stepX;
      const clampedScore = Math.min(100, Math.max(0, point.score));
      const y =
        CHART_PADDING_TOP + (1 - clampedScore / 100) * innerH;

      return { x, y };
    });

    const linePath = xy
      .map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
      .join(' ');

    const areaPath = `${linePath} L ${xy[xy.length - 1]!.x.toFixed(1)} ${
      CHART_PADDING_TOP + innerH
    } L ${xy[0]!.x.toFixed(1)} ${CHART_PADDING_TOP + innerH} Z`;

    return { xy, linePath, areaPath, innerW, innerH };
  }, [points, width]);

  const formatDate = useMemo(() => {
    return new Intl.DateTimeFormat(i18n.language, {
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      month: 'short',
    });
  }, [i18n.language]);

  const handleMove = (event: React.MouseEvent<SVGSVGElement>) => {
    if (geometry == null || svgRef.current == null) {
      return;
    }

    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = rect.width / width;
    const xPx = (event.clientX - rect.left) / Math.max(scaleX, 0.001);

    let closest = 0;
    let closestDist = Infinity;
    for (let idx = 0; idx < geometry.xy.length; idx += 1) {
      const dist = Math.abs(geometry.xy[idx]!.x - xPx);
      if (dist < closestDist) {
        closestDist = dist;
        closest = idx;
      }
    }

    setHoverIndex(closest);
  };

  const handleLeave = () => setHoverIndex(null);

  const hovered =
    hoverIndex != null ? points[hoverIndex] ?? null : null;
  const hoveredXY =
    geometry != null && hoverIndex != null
      ? geometry.xy[hoverIndex] ?? null
      : null;

  return (
    <section
      aria-label={t('risk.history.title')}
      className="panel host-risk-history"
    >
      <header className="host-risk-history-header">
        <h3 className="host-risk-history-title">{t('risk.history.title')}</h3>
        <div className="segmented-control" role="tablist">
          {RANGES.map((r) => (
            <button
              aria-pressed={range === r.id}
              className={range === r.id ? 'segmented-active' : 'secondary'}
              key={r.id}
              onClick={() => setRange(r.id)}
              type="button"
            >
              {t(r.labelKey)}
            </button>
          ))}
        </div>
      </header>

      <div className="host-risk-history-chart-wrap" ref={containerRef}>
        {loading && (
          <p className="host-risk-history-meta">{t('common.loading')}</p>
        )}
        {!loading && error != null && (
          <p className="host-risk-history-meta">{error}</p>
        )}
        {!loading && error == null && points.length === 0 && (
          <p className="host-risk-history-meta">{t('risk.history.empty')}</p>
        )}
        {!loading && error == null && geometry != null && (
          <svg
            aria-hidden
            className="host-risk-history-svg"
            height={CHART_HEIGHT}
            onMouseLeave={handleLeave}
            onMouseMove={handleMove}
            preserveAspectRatio="none"
            ref={svgRef}
            viewBox={`0 0 ${width} ${CHART_HEIGHT}`}
            width="100%"
          >
            <line
              className="host-risk-history-grid"
              x1={CHART_PADDING_X}
              x2={width - CHART_PADDING_X}
              y1={CHART_PADDING_TOP + geometry.innerH / 2}
              y2={CHART_PADDING_TOP + geometry.innerH / 2}
            />
            <path className="host-risk-history-area" d={geometry.areaPath} />
            <path className="host-risk-history-line" d={geometry.linePath} />
            {hoveredXY != null && hovered != null && (
              <>
                <line
                  className="host-risk-history-cursor"
                  x1={hoveredXY.x}
                  x2={hoveredXY.x}
                  y1={CHART_PADDING_TOP}
                  y2={CHART_PADDING_TOP + geometry.innerH}
                />
                <circle
                  className="host-risk-history-dot"
                  cx={hoveredXY.x}
                  cy={hoveredXY.y}
                  r={3}
                />
              </>
            )}
          </svg>
        )}

        {hovered != null && (
          <div className="host-risk-history-tooltip" role="status">
            <strong>{hovered.score}</strong>
            <span>
              {formatDate.format(new Date(hovered.captured_at))} · P{' '}
              {Math.round(hovered.probability * 100)}% · I{' '}
              {Math.round(hovered.impact * 100)}% · C{' '}
              {Math.round(hovered.confidence * 100)}%
            </span>
          </div>
        )}
      </div>
    </section>
  );
}
