import {
  ArrowLeft,
  ChevronRight,
  Gauge,
  GitFork,
  Maximize2,
  Network,
  RotateCcw,
  ShieldAlert,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import {
  type CSSProperties,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import ForceGraph2D, {
  type ForceGraphMethods,
  type LinkObject,
  type NodeObject,
} from 'react-force-graph-2d';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { EmptyState } from '@components/EmptyState';
import { InlineError } from '@components/InlineError';
import { ProbabilityBar } from '@components/ProbabilityBar';
import { SkeletonRow } from '@components/Skeleton';
import { StatTile, StatTileRow, type StatTileTone } from '@components/StatTile';
import { Tooltip } from '@components/Tooltip';
import { isAbortError } from '@helpers/abortError';
import { relationTypeLabel } from '@helpers/attackPathLabels';
import { formatRelative } from '@helpers/format';
import { getAttackPath } from '@services/AttackPathAPI';
import { bucketForScore } from '@/types/risk';
import type { AttackPathRelation, AttackPathView } from '@/types/attackPath';

type GraphNode = {
  id: string;
  hostId: number;
  label: string;
  isFocal: boolean;
  // Deterministic radial layout pins each node via fx/fy (see the graph memo),
  // so the force engine never moves them and the fit can be computed exactly.
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
};

type GraphLink = {
  source: string;
  target: string;
  relationType: string;
  strength: number;
  curvature: number;
};

// Map relation kinds to the project's design tokens so dark/light theme
// switches and any future palette change carry through without touching
// this file. CSS variables are read once per render via a small helper.
const RELATION_TOKENS: Record<string, string> = {
  shared_subnet: '--accent',
  shared_asn: '--primary',
  shared_cert: '--danger',
  shared_favicon: '--success',
};

const NODE_FOCAL_TOKEN = '--danger';
const NODE_NEIGHBOUR_TOKEN = '--primary';
const NODE_SELECTED_TOKEN = '--accent';
const NODE_FALLBACK_TOKEN = '--text-muted';

const TONE_BY_BUCKET: Record<string, StatTileTone> = {
  critical: 'danger',
  high: 'warning',
  medium: 'default',
  low: 'muted',
};

function toneForFraction(fraction: number): StatTileTone {
  return TONE_BY_BUCKET[bucketForScore(fraction * 100)] ?? 'default';
}

function tokenColor(token: string, fallback = '#94a3b8'): string {
  if (typeof window === 'undefined') {
    return fallback;
  }

  const value = getComputedStyle(document.documentElement)
    .getPropertyValue(token)
    .trim();

  return value !== '' ? value : fallback;
}

// Small colour utilities for canvas drawing (gradients, glows, translucency).
// tokenColor() returns hex from the CSS variables, so we parse that.
function hexToRgb(hex: string): [number, number, number] | null {
  const match = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(hex.trim());
  const group = match?.[1];
  if (group == null) {
    return null;
  }

  const full =
    group.length === 3
      ? group
          .split('')
          .map((c) => c + c)
          .join('')
      : group;
  const num = parseInt(full, 16);

  return [(num >> 16) & 255, (num >> 8) & 255, num & 255];
}

function withAlpha(color: string, alpha: number): string {
  const rgb = hexToRgb(color);
  if (rgb == null) {
    return color;
  }

  const [r, g, b] = rgb;

  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function mixHex(from: string, to: string, t: number): string {
  const a = hexToRgb(from);
  const b = hexToRgb(to);
  if (a == null || b == null) {
    return from;
  }

  const r = Math.round(a[0] + (b[0] - a[0]) * t);
  const g = Math.round(a[1] + (b[1] - a[1]) * t);
  const bl = Math.round(a[2] + (b[2] - a[2]) * t);

  return `rgb(${r}, ${g}, ${bl})`;
}

// Force-graph mutates link endpoints from ids into node objects once the
// simulation runs, so callbacks must resolve either shape back to an id.
function endpointId(end: unknown): string {
  if (end != null && typeof end === 'object' && 'id' in end) {
    return String((end as { id: unknown }).id);
  }

  return String(end);
}

export function AttackPathPage() {
  const { t } = useTranslation();
  const { ip = '' } = useParams();
  const navigate = useNavigate();
  const [view, setView] = useState<AttackPathView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const graphResizeObserver = useRef<ResizeObserver | null>(null);
  const fgRef = useRef<
    | ForceGraphMethods<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>>
    | undefined
  >(undefined);
  const [size, setSize] = useState({ width: 600, height: 480 });
  const [selectedRelationTypes, setSelectedRelationTypes] = useState<
    Set<string>
  >(new Set());
  const [strengthThreshold, setStrengthThreshold] = useState(0);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  useEffect(() => {
    if (ip === '') {
      return;
    }

    const controller = new AbortController();

    setLoading(true);
    setError(null);
    setView(null);
    setSelectedNodeId(null);

    getAttackPath(ip, controller.signal)
      .then((data) => setView(data))
      .catch((err: unknown) => {
        if (isAbortError(err)) {
          return;
        }

        setError(t('risk.attackPath.errorLoading'));
      })
      .finally(() => setLoading(false));

    return () => controller.abort();
  }, [ip, reloadKey, t]);

  // Measure the graph container via a callback ref + ResizeObserver. The
  // container only mounts after data has loaded (it sits behind a loading
  // guard), so a mount-time effect would attach before it exists and never
  // re-run — leaving the canvas stuck at its default size. A callback ref fires
  // exactly when the element attaches/detaches.
  const measureGraphContainer = useCallback((el: HTMLDivElement | null) => {
    graphResizeObserver.current?.disconnect();
    graphResizeObserver.current = null;

    if (el == null) {
      return;
    }

    const sync = () => {
      setSize({
        width: Math.max(el.clientWidth, 320),
        height: Math.max(el.clientHeight, 400),
      });
    };

    sync();
    const observer = new ResizeObserver(sync);
    observer.observe(el);
    graphResizeObserver.current = observer;
  }, []);

  const hostByID = useMemo(() => {
    if (view == null) {
      return new Map<number, string>();
    }

    return new Map(view.hosts.map((host) => [host.host_id, host.ip]));
  }, [view]);

  const filteredRelations = useMemo<AttackPathRelation[]>(() => {
    if (view == null) {
      return [];
    }

    return view.relations.filter(
      (relation) =>
        (selectedRelationTypes.size === 0 ||
          selectedRelationTypes.has(relation.relation_type)) &&
        relation.strength >= strengthThreshold
    );
  }, [selectedRelationTypes, strengthThreshold, view]);

  const graph = useMemo(() => {
    const degreeById = new Map<string, number>();
    const nodeTypeById = new Map<string, string>();

    if (view == null) {
      return {
        nodes: [] as GraphNode[],
        links: [] as GraphLink[],
        degreeById,
        nodeTypeById,
        maxDegree: 0,
      };
    }

    const focalId = String(view.score.host_id);
    const nodeIds = new Set<string>([focalId]);
    const links: GraphLink[] = [];
    // Track the strongest incident relation per node so neighbour colour
    // matches the relation legend, and group parallel edges to bow them apart.
    const bestStrengthByNode = new Map<string, number>();
    const pairBuckets = new Map<string, GraphLink[]>();

    const rememberType = (id: string, type: string, strength: number) => {
      if (strength >= (bestStrengthByNode.get(id) ?? -1)) {
        bestStrengthByNode.set(id, strength);
        nodeTypeById.set(id, type);
      }
    };

    for (const relation of filteredRelations) {
      const src = String(relation.src_host_id);
      const dst = String(relation.dst_host_id);
      nodeIds.add(src);
      nodeIds.add(dst);
      degreeById.set(src, (degreeById.get(src) ?? 0) + 1);
      degreeById.set(dst, (degreeById.get(dst) ?? 0) + 1);
      rememberType(src, relation.relation_type, relation.strength);
      rememberType(dst, relation.relation_type, relation.strength);

      const link: GraphLink = {
        source: src,
        target: dst,
        relationType: relation.relation_type,
        strength: relation.strength,
        curvature: 0,
      };
      const pairKey = src < dst ? `${src}|${dst}` : `${dst}|${src}`;
      const bucket = pairBuckets.get(pairKey) ?? [];
      bucket.push(link);
      pairBuckets.set(pairKey, bucket);
      links.push(link);
    }

    for (const bucket of pairBuckets.values()) {
      if (bucket.length < 2) {
        continue;
      }

      // Spread parallel edges symmetrically around the straight line.
      const step = 0.36 / bucket.length;
      bucket.forEach((link, index) => {
        link.curvature = (index - (bucket.length - 1) / 2) * step * 2;
      });
    }

    const nodes: GraphNode[] = Array.from(nodeIds).map((id) => ({
      id,
      hostId: Number(id),
      label: hostByID.get(Number(id)) ?? `#${id}`,
      isFocal: id === focalId,
    }));

    // Deterministic radial layout: focal pinned at the centre, neighbours evenly
    // spaced on a ring (stable order by host id). Pinning x/y + fx/fy means the
    // force engine can't drift them, so positions are known up-front and the fit
    // is exact — no physics jitter, off-centring, or label clipping.
    const ringRadius = 120;
    const neighbours = nodes
      .filter((node) => !node.isFocal)
      .sort((a, b) => a.hostId - b.hostId);

    for (const node of nodes) {
      if (node.isFocal) {
        node.x = node.fx = 0;
        node.y = node.fy = 0;
      }
    }

    neighbours.forEach((node, index) => {
      const angle =
        -Math.PI / 2 + (2 * Math.PI * index) / Math.max(1, neighbours.length);
      node.x = node.fx = ringRadius * Math.cos(angle);
      node.y = node.fy = ringRadius * Math.sin(angle);
    });

    let maxDegree = 0;
    for (const degree of degreeById.values()) {
      if (degree > maxDegree) {
        maxDegree = degree;
      }
    }

    return { nodes, links, degreeById, nodeTypeById, maxDegree };
  }, [filteredRelations, hostByID, view]);

  const focalNodeId = view != null ? String(view.score.host_id) : '';

  // Resolved hex colour for a node id: the focal hub is red, neighbours take
  // their strongest relation colour. Used by node fills and edge gradients.
  const nodeColor = useCallback(
    (nodeId: string) =>
      nodeId === focalNodeId
        ? tokenColor(NODE_FOCAL_TOKEN)
        : tokenColor(
            RELATION_TOKENS[graph.nodeTypeById.get(nodeId) ?? ''] ??
              NODE_NEIGHBOUR_TOKEN
          ),
    [focalNodeId, graph]
  );

  // Relation types present in the current view, in legend order.
  const presentRelationTypes = useMemo(() => {
    const present = new Set(filteredRelations.map((r) => r.relation_type));

    return Object.keys(RELATION_TOKENS).filter((type) => present.has(type));
  }, [filteredRelations]);

  // Fit the deterministic radial layout to the canvas. Each node contributes a
  // bounding box of its dot (graph units, scales with zoom) plus its outward
  // label (constant screen px). We binary-search the largest zoom at which the
  // whole content box fits both width and height, then centre that box — so the
  // graph fills whichever dimension binds, stays balanced, and never clips.
  const fitGraph = useCallback(() => {
    const fg = fgRef.current;
    if (fg == null) {
      return;
    }

    const ctx = document.createElement('canvas').getContext('2d');
    if (ctx != null) {
      ctx.font = '500 12px "Space Grotesk", sans-serif';
    }

    const gap = 10; // node-to-label gap + pill padding
    const labelHalfHeight = 8;
    const items = graph.nodes
      .filter((n) => n.x != null && n.y != null)
      .map((n) => {
        const degree = graph.degreeById.get(String(n.id)) ?? 0;
        const ratio = graph.maxDegree > 0 ? degree / graph.maxDegree : 0;
        const baseRadius = 4 + ratio * 5;
        return {
          x: n.x as number,
          y: n.y as number,
          radius: n.isFocal ? Math.max(8, baseRadius + 2) : baseRadius,
          labelWidth: ctx != null ? ctx.measureText(n.label).width : 0,
          onRight: (n.x as number) >= 0,
        };
      });

    if (items.length === 0) {
      return;
    }

    const pad = 24;
    const availWidth = Math.max(50, size.width - 2 * pad);
    const availHeight = Math.max(50, size.height - 2 * pad);

    // Content bounding box (screen px relative to the graph origin) at a zoom.
    const extentAt = (zoom: number) => {
      let minX = Infinity;
      let maxX = -Infinity;
      let minY = Infinity;
      let maxY = -Infinity;

      for (const it of items) {
        const cx = it.x * zoom;
        const cy = it.y * zoom;
        const r = it.radius * zoom;
        const left = it.onRight ? cx - r : cx - r - gap - it.labelWidth;
        const right = it.onRight ? cx + r + gap + it.labelWidth : cx + r;

        minX = Math.min(minX, left);
        maxX = Math.max(maxX, right);
        minY = Math.min(minY, cy - r - labelHalfHeight);
        maxY = Math.max(maxY, cy + r + labelHalfHeight);
      }

      return { minX, maxX, minY, maxY };
    };

    let lo = 0.05;
    let hi = 40;
    for (let i = 0; i < 40; i += 1) {
      const mid = (lo + hi) / 2;
      const e = extentAt(mid);
      if (e.maxX - e.minX <= availWidth && e.maxY - e.minY <= availHeight) {
        lo = mid;
      } else {
        hi = mid;
      }
    }

    const zoom = lo;
    const e = extentAt(zoom);

    // Apply zoom *before* centring: centerAt() computes the pan from the
    // current zoom, so doing both with a shared tween races and mis-positions
    // the graph. Setting zoom first (instant) makes the centre exact.
    fg.zoom(zoom, 0);
    fg.centerAt((e.minX + e.maxX) / 2 / zoom, (e.minY + e.maxY) / 2 / zoom, 0);
  }, [graph, size.width, size.height]);

  // Positions are known synchronously, so re-fit whenever the graph or canvas
  // size changes (rAF lets the renderer apply the pinned coords first).
  useEffect(() => {
    const id = requestAnimationFrame(() => fitGraph());

    return () => cancelAnimationFrame(id);
  }, [fitGraph]);

  // Selection wins; hover gives a transient neighbourhood preview.
  const highlightId = selectedNodeId ?? hoveredNodeId;

  const highlight = useMemo(() => {
    const nodes = new Set<string>();

    if (
      highlightId == null ||
      !graph.nodes.some((node) => node.id === highlightId)
    ) {
      return { nodes, active: false };
    }

    nodes.add(highlightId);
    for (const relation of filteredRelations) {
      const src = String(relation.src_host_id);
      const dst = String(relation.dst_host_id);

      if (src === highlightId) {
        nodes.add(dst);
      } else if (dst === highlightId) {
        nodes.add(src);
      }
    }

    return { nodes, active: true };
  }, [filteredRelations, graph, highlightId]);

  const typeCounts = useMemo(() => {
    const counts = new Map<string, number>();

    if (view == null) {
      return counts;
    }

    for (const relation of view.relations) {
      counts.set(
        relation.relation_type,
        (counts.get(relation.relation_type) ?? 0) + 1
      );
    }

    return counts;
  }, [view]);

  const selectedNode = useMemo(
    () =>
      graph.nodes.find((node) => node.id === selectedNodeId && !node.isFocal) ??
      null,
    [graph, selectedNodeId]
  );

  const relationsForDetail = useMemo<AttackPathRelation[]>(() => {
    if (selectedNode == null) {
      return filteredRelations;
    }

    return filteredRelations.filter(
      (relation) =>
        relation.src_host_id === selectedNode.hostId ||
        relation.dst_host_id === selectedNode.hostId
    );
  }, [filteredRelations, selectedNode]);

  const groupedRelations = useMemo(() => {
    const map = new Map<string, AttackPathRelation[]>();

    for (const relation of relationsForDetail) {
      const list = map.get(relation.relation_type) ?? [];
      list.push(relation);
      map.set(relation.relation_type, list);
    }

    for (const list of map.values()) {
      list.sort((a, b) => b.strength - a.strength);
    }

    return map;
  }, [relationsForDetail]);

  const strongestType = useMemo(() => {
    let best: string | null = null;
    let bestStrength = -1;

    for (const [type, list] of groupedRelations.entries()) {
      const top = list[0]?.strength ?? 0;

      if (top > bestStrength) {
        bestStrength = top;
        best = type;
      }
    }

    return best;
  }, [groupedRelations]);

  const handleZoom = (factor: number) => {
    const current = fgRef.current?.zoom() ?? 1;
    fgRef.current?.zoom(current * factor, 250);
  };

  const handleFit = () => {
    fitGraph();
  };

  const handleReset = () => {
    setSelectedNodeId(null);
    fitGraph();
  };

  const freshness = view?.score.computed_at
    ? formatRelative(view.score.computed_at)
    : '';
  const pivotBucket =
    view != null ? bucketForScore(view.score.pivot_score * 100) : 'low';
  const hasData = view != null && view.relations.length > 0;

  return (
    <section className="page attack-path-page">
      <div className="page-header">
        <div>
          <div className="attack-path-title-row">
            <h1>{t('risk.attackPath.title', { ip })}</h1>
            {hasData && (
              <span className="attack-path-pivot-chip">
                <span className="attack-path-pivot-label">
                  {t('risk.attackPath.pivotScore')}
                </span>
                <span className={`risk-badge risk-${pivotBucket}`}>
                  {t(`risk.bucket.${pivotBucket}`)}
                </span>
              </span>
            )}
            {view != null && view.score.reachable_critical_count > 0 && (
              <span className="attack-path-critical-pill">
                <ShieldAlert aria-hidden size={12} />
                {t('risk.attackPath.criticalReachable', {
                  count: view.score.reachable_critical_count,
                })}
              </span>
            )}
          </div>
          <p>{t('risk.attackPath.subtitle')}</p>
          {freshness !== '' && (
            <p className="attack-path-freshness">
              {t('risk.attackPath.updatedAt', { when: freshness })}
            </p>
          )}
        </div>
        <div className="header-actions">
          <Link
            className="button-secondary"
            to={`/hosts/${encodeURIComponent(ip)}`}
          >
            <ArrowLeft aria-hidden size={16} />
            {t('risk.attackPath.backToHost')}
          </Link>
        </div>
      </div>

      {!loading && error == null && hasData && view != null && (
        <StatTileRow>
          <StatTile
            icon={<Gauge size={18} />}
            label={t('risk.attackPath.centrality')}
            tone={toneForFraction(view.score.centrality)}
            value={`${(view.score.centrality * 100).toFixed(0)}%`}
          />
          <StatTile
            icon={<GitFork size={18} />}
            label={t('risk.attackPath.pivotScore')}
            tone={toneForFraction(view.score.pivot_score)}
            value={`${(view.score.pivot_score * 100).toFixed(0)}%`}
          />
          <StatTile
            icon={<ShieldAlert size={18} />}
            label={t('risk.attackPath.reachableCritical')}
            tone={
              view.score.reachable_critical_count > 0 ? 'danger' : 'default'
            }
            value={view.score.reachable_critical_count}
          />
          <StatTile
            icon={<Network size={18} />}
            label={t('risk.attackPath.kpiNeighbours')}
            value={Math.max(0, graph.nodes.length - 1)}
          />
        </StatTileRow>
      )}

      {hasData && view != null && (
        <section className="panel attack-path-toolbar">
          <div className="attack-path-filters" role="group">
            {Object.keys(RELATION_TOKENS).map((type) => {
              const active = selectedRelationTypes.has(type);
              const count = typeCounts.get(type) ?? 0;

              return (
                <button
                  aria-pressed={active}
                  className={
                    active
                      ? 'attack-path-filter-chip is-active'
                      : 'attack-path-filter-chip'
                  }
                  key={type}
                  onClick={() =>
                    setSelectedRelationTypes((current) => {
                      const next = new Set(current);
                      if (next.has(type)) {
                        next.delete(type);
                      } else {
                        next.add(type);
                      }

                      return next;
                    })
                  }
                  style={
                    {
                      '--chip-color': tokenColor(
                        RELATION_TOKENS[type] ?? NODE_FALLBACK_TOKEN
                      ),
                    } as CSSProperties
                  }
                  type="button"
                >
                  <span aria-hidden className="attack-path-rel-dot" />
                  {relationTypeLabel(type, t)}
                  <span
                    className="attack-path-filter-count"
                    data-zero={count === 0 ? '' : undefined}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
            <button
              aria-pressed={selectedRelationTypes.size === 0}
              className={
                selectedRelationTypes.size === 0
                  ? 'attack-path-filter-chip is-active'
                  : 'attack-path-filter-chip'
              }
              onClick={() => setSelectedRelationTypes(new Set())}
              style={{ '--chip-color': 'var(--primary)' } as CSSProperties}
              type="button"
            >
              {t('risk.attackPath.filterAll')}
            </button>
          </div>
          <label className="attack-path-threshold">
            <span className="search-field-label">
              {t('risk.attackPath.strengthThreshold')}
            </span>
            <div className="attack-path-threshold-row">
              <input
                className="attack-path-range"
                max={1}
                min={0}
                onChange={(event) =>
                  setStrengthThreshold(Number(event.target.value))
                }
                step={0.05}
                style={
                  {
                    '--fill': `${strengthThreshold * 100}%`,
                  } as CSSProperties
                }
                type="range"
                value={strengthThreshold}
              />
              <span className="attack-path-threshold-value">
                {t('risk.attackPath.thresholdValue', {
                  value: strengthThreshold.toFixed(2),
                })}
              </span>
            </div>
          </label>
          <p className="attack-path-showing muted-text">
            {t('risk.attackPath.showingRelations', {
              shown: filteredRelations.length,
              total: view.relations.length,
            })}
          </p>
        </section>
      )}

      {loading && (
        <section className="panel attack-path-loading-panel">
          <table className="risk-events-table">
            <tbody>
              <SkeletonRow cells={['long', 'mid', 'short']} />
              <SkeletonRow cells={['mid', 'long', 'short']} />
              <SkeletonRow cells={['long', 'short', 'mid']} />
            </tbody>
          </table>
        </section>
      )}
      {!loading && error != null && (
        <InlineError
          message={error}
          onRetry={() => setReloadKey((k) => k + 1)}
        />
      )}

      {!loading && error == null && view != null && !hasData && (
        <section className="panel attack-path-empty-panel">
          <EmptyState
            icon={<Network size={22} />}
            title={t('risk.attackPath.empty')}
            hint={t('risk.attackPath.emptyHint')}
          />
        </section>
      )}

      {!loading && error == null && hasData && view != null && (
        <div className="attack-path-layout">
          <div className="panel attack-path-graph" ref={measureGraphContainer}>
            {graph.nodes.length <= 1 ? (
              <EmptyState
                icon={<Network size={22} />}
                title={t('risk.attackPath.noMatch')}
                hint={t('risk.attackPath.noMatchHint')}
                action={
                  <button
                    className="secondary"
                    onClick={() => {
                      setSelectedRelationTypes(new Set());
                      setStrengthThreshold(0);
                    }}
                    type="button"
                  >
                    {t('risk.attackPath.clearFilters')}
                  </button>
                }
              />
            ) : (
              <>
                <div className="attack-path-graph-controls">
                  <button
                    aria-label={t('risk.attackPath.zoomIn')}
                    onClick={() => handleZoom(1.4)}
                    title={t('risk.attackPath.zoomIn')}
                    type="button"
                  >
                    <ZoomIn aria-hidden size={16} />
                  </button>
                  <button
                    aria-label={t('risk.attackPath.zoomOut')}
                    onClick={() => handleZoom(0.7)}
                    title={t('risk.attackPath.zoomOut')}
                    type="button"
                  >
                    <ZoomOut aria-hidden size={16} />
                  </button>
                  <button
                    aria-label={t('risk.attackPath.fitView')}
                    onClick={handleFit}
                    title={t('risk.attackPath.fitView')}
                    type="button"
                  >
                    <Maximize2 aria-hidden size={16} />
                  </button>
                  <button
                    aria-label={t('risk.attackPath.resetView')}
                    onClick={handleReset}
                    title={t('risk.attackPath.resetView')}
                    type="button"
                  >
                    <RotateCcw aria-hidden size={16} />
                  </button>
                </div>
                {presentRelationTypes.length > 0 && (
                  <div className="attack-path-legend">
                    {presentRelationTypes.map((type) => (
                      <span className="attack-path-legend-item" key={type}>
                        <span
                          aria-hidden
                          className="attack-path-legend-dot"
                          style={
                            {
                              background: tokenColor(
                                RELATION_TOKENS[type] ?? NODE_FALLBACK_TOKEN
                              ),
                            } as CSSProperties
                          }
                        />
                        {relationTypeLabel(type, t)}
                      </span>
                    ))}
                  </div>
                )}
                <ForceGraph2D
                  cooldownTicks={0}
                  enableNodeDrag={false}
                  graphData={graph}
                  height={size.height}
                  linkCanvasObjectMode={() => 'replace'}
                  linkCanvasObject={(link, ctx) => {
                    const l = link as GraphLink;
                    const source = l.source as unknown as {
                      x?: number;
                      y?: number;
                    };
                    const target = l.target as unknown as {
                      x?: number;
                      y?: number;
                    };

                    if (
                      source?.x == null ||
                      source?.y == null ||
                      target?.x == null ||
                      target?.y == null
                    ) {
                      return;
                    }

                    const srcId = endpointId(l.source);
                    const tgtId = endpointId(l.target);
                    const incident =
                      !highlight.active ||
                      srcId === highlightId ||
                      tgtId === highlightId;

                    // Gradient fades from each endpoint's own colour (focal red,
                    // neighbours their relation colour) — edges flow into the hub.
                    const gradient = ctx.createLinearGradient(
                      source.x,
                      source.y,
                      target.x,
                      target.y
                    );
                    gradient.addColorStop(0, nodeColor(srcId));
                    gradient.addColorStop(1, nodeColor(tgtId));

                    ctx.save();
                    ctx.globalAlpha = highlight.active
                      ? incident
                        ? 0.9
                        : 0.12
                      : 0.55;
                    ctx.strokeStyle = gradient;
                    ctx.lineWidth =
                      Math.max(0.5, l.strength * 3) * (incident ? 1 : 0.6);
                    ctx.lineCap = 'round';
                    ctx.beginPath();
                    ctx.moveTo(source.x, source.y);

                    if (l.curvature !== 0) {
                      const mx = (source.x + target.x) / 2;
                      const my = (source.y + target.y) / 2;
                      const dx = target.x - source.x;
                      const dy = target.y - source.y;
                      ctx.quadraticCurveTo(
                        mx + dy * l.curvature,
                        my - dx * l.curvature,
                        target.x,
                        target.y
                      );
                    } else {
                      ctx.lineTo(target.x, target.y);
                    }

                    ctx.stroke();
                    ctx.restore();
                  }}
                  nodeCanvasObject={(node, ctx, scale) => {
                    const n = node as NodeObject<GraphNode> & {
                      x?: number;
                      y?: number;
                    };

                    if (n.x == null || n.y == null) {
                      return;
                    }

                    const id = String(n.id);
                    const degree = graph.degreeById.get(id) ?? 0;
                    const ratio =
                      graph.maxDegree > 0 ? degree / graph.maxDegree : 0;
                    const baseRadius = 4 + ratio * 5;
                    const radius = n.isFocal
                      ? Math.max(8, baseRadius + 2)
                      : baseRadius;
                    const isSelected = id === selectedNodeId;
                    const isHovered = id === hoveredNodeId;
                    const dimmed = highlight.active && !highlight.nodes.has(id);
                    const nodeToken = n.isFocal
                      ? NODE_FOCAL_TOKEN
                      : (RELATION_TOKENS[graph.nodeTypeById.get(id) ?? ''] ??
                        NODE_NEIGHBOUR_TOKEN);

                    const alpha = dimmed ? 0.2 : 1;
                    const baseColor = tokenColor(nodeToken);

                    ctx.save();

                    // Soft halo behind the focal / selected / hovered node.
                    if (n.isFocal || isSelected || isHovered) {
                      const haloColor =
                        isSelected && !n.isFocal
                          ? tokenColor(NODE_SELECTED_TOKEN)
                          : baseColor;
                      ctx.globalAlpha = alpha * 0.22;
                      ctx.beginPath();
                      ctx.arc(
                        n.x,
                        n.y,
                        radius + (n.isFocal ? 6 : 4),
                        0,
                        2 * Math.PI
                      );
                      ctx.fillStyle = haloColor;
                      ctx.fill();
                    }

                    // Node body: soft drop shadow for depth + a gentle sphere
                    // gradient (lightened top-left → base colour).
                    ctx.globalAlpha = alpha;
                    ctx.shadowColor = withAlpha(baseColor, 0.35);
                    ctx.shadowBlur = 6;
                    const fill = ctx.createRadialGradient(
                      n.x - radius * 0.4,
                      n.y - radius * 0.4,
                      radius * 0.1,
                      n.x,
                      n.y,
                      radius
                    );
                    fill.addColorStop(0, mixHex(baseColor, '#ffffff', 0.4));
                    fill.addColorStop(1, baseColor);
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, radius, 0, 2 * Math.PI);
                    ctx.fillStyle = fill;
                    ctx.fill();

                    // Thin surface ring separates the dot from edges/labels.
                    ctx.shadowBlur = 0;
                    ctx.lineWidth = 1;
                    ctx.strokeStyle = tokenColor('--surface', '#ffffff');
                    ctx.stroke();

                    // Coloured accent ring for the focal hub / selected node.
                    if (n.isFocal || isSelected) {
                      ctx.lineWidth = 1.5;
                      ctx.strokeStyle =
                        isSelected && !n.isFocal
                          ? tokenColor(NODE_SELECTED_TOKEN)
                          : tokenColor(NODE_FOCAL_TOKEN);
                      ctx.beginPath();
                      ctx.arc(n.x, n.y, radius + 1.5, 0, 2 * Math.PI);
                      ctx.stroke();
                    }

                    if (scale > 0.9 || n.isFocal || isSelected || isHovered) {
                      // Keep labels a constant ~12px on screen at any zoom so the
                      // fit's width reservation stays exact (no clipping) and they
                      // don't balloon when the graph zooms in to fill the area.
                      const fontSize = 12 / scale;
                      ctx.font = `${n.isFocal ? 600 : 500} ${fontSize}px "Space Grotesk", sans-serif`;
                      ctx.textBaseline = 'middle';

                      // The focal node sits at the origin, so a node's side is
                      // just the sign of its x: right-half labels extend right,
                      // left-half extend left — neither runs off after the fit.
                      const onRight = n.x >= 0;
                      ctx.textAlign = onRight ? 'left' : 'right';

                      const padX = 5 / scale;
                      const padY = 3 / scale;
                      const gap = 4 / scale;
                      const width = ctx.measureText(n.label).width;
                      const textX = onRight
                        ? n.x + radius + gap
                        : n.x - radius - gap;
                      const rectX = onRight
                        ? textX - padX
                        : textX - width - padX;
                      const rectY = n.y - fontSize / 2 - padY;
                      const rectW = width + padX * 2;
                      const rectH = fontSize + padY * 2;

                      ctx.globalAlpha = alpha;
                      ctx.beginPath();
                      if (typeof ctx.roundRect === 'function') {
                        ctx.roundRect(rectX, rectY, rectW, rectH, rectH / 2);
                      } else {
                        ctx.rect(rectX, rectY, rectW, rectH);
                      }
                      ctx.fillStyle = withAlpha(
                        tokenColor('--surface', '#ffffff'),
                        0.92
                      );
                      ctx.fill();
                      ctx.lineWidth = 1 / scale;
                      ctx.strokeStyle = withAlpha(
                        tokenColor('--border', '#dbe3ef'),
                        0.9
                      );
                      ctx.stroke();

                      ctx.fillStyle = tokenColor('--text', '#0f172a');
                      ctx.fillText(n.label, textX, n.y);
                    }

                    ctx.restore();
                  }}
                  nodeLabel={(node) => (node as GraphNode).label}
                  onBackgroundClick={() => setSelectedNodeId(null)}
                  onEngineStop={() => fitGraph()}
                  onNodeHover={(node) =>
                    setHoveredNodeId(
                      node != null ? String((node as GraphNode).id) : null
                    )
                  }
                  onNodeClick={(node, event) => {
                    const n = node as NodeObject<GraphNode>;
                    const id = String(n.id);

                    if (event != null && event.detail >= 2) {
                      const nodeIP = hostByID.get(Number(n.hostId));

                      if (nodeIP != null && nodeIP !== '') {
                        navigate(`/attack-paths/${encodeURIComponent(nodeIP)}`);
                      }

                      return;
                    }

                    setSelectedNodeId(id);
                  }}
                  ref={fgRef}
                  width={size.width}
                />
              </>
            )}
          </div>

          <aside className="panel attack-path-sidebar">
            {selectedNode != null ? (
              <div className="attack-path-detail-head">
                <h2>{t('risk.attackPath.selectedHost')}</h2>
                <p className="attack-path-detail-ip">{selectedNode.label}</p>
                <dl className="attack-path-stats">
                  <div>
                    <dt>{t('risk.attackPath.degree')}</dt>
                    <dd>{graph.degreeById.get(selectedNode.id) ?? 0}</dd>
                  </div>
                </dl>
                <Link
                  className="primary attack-path-open-btn"
                  to={`/attack-paths/${encodeURIComponent(selectedNode.label)}`}
                >
                  {t('risk.attackPath.openHostPaths')}
                </Link>
              </div>
            ) : (
              <div className="attack-path-detail-head">
                <h2>{t('risk.attackPath.focal')}</h2>
                <dl className="attack-path-stats">
                  <div>
                    <dt>
                      <Tooltip label={t('risk.attackPath.centralityHelp')}>
                        <span className="attack-path-help">
                          {t('risk.attackPath.centrality')}
                        </span>
                      </Tooltip>
                    </dt>
                    <dd className="attack-path-stat-meter">
                      <ProbabilityBar
                        ariaLabel={t('risk.attackPath.centrality')}
                        value={view.score.centrality}
                      />
                      <span>{(view.score.centrality * 100).toFixed(1)}%</span>
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <Tooltip label={t('risk.attackPath.pivotHelp')}>
                        <span className="attack-path-help">
                          {t('risk.attackPath.pivotScore')}
                        </span>
                      </Tooltip>
                    </dt>
                    <dd className="attack-path-stat-meter">
                      <ProbabilityBar
                        ariaLabel={t('risk.attackPath.pivotScore')}
                        value={view.score.pivot_score}
                      />
                      <span>{(view.score.pivot_score * 100).toFixed(1)}%</span>
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <Tooltip
                        label={t('risk.attackPath.reachableCriticalHelp')}
                      >
                        <span className="attack-path-help">
                          {t('risk.attackPath.reachableCritical')}
                        </span>
                      </Tooltip>
                    </dt>
                    <dd
                      className={
                        view.score.reachable_critical_count > 0
                          ? 'attack-path-critical-value'
                          : undefined
                      }
                    >
                      {view.score.reachable_critical_count}
                    </dd>
                  </div>
                </dl>
              </div>
            )}

            <h3>{t('risk.attackPath.relations')}</h3>
            {groupedRelations.size === 0 ? (
              <p className="muted-text">{t('risk.attackPath.empty')}</p>
            ) : (
              Array.from(groupedRelations.entries()).map(([type, list]) => (
                <details
                  className="attack-path-relgroup"
                  key={type}
                  open={type === strongestType}
                >
                  <summary>
                    <span
                      aria-hidden
                      className="attack-path-rel-dot"
                      style={{
                        background: tokenColor(
                          RELATION_TOKENS[type] ?? NODE_FALLBACK_TOKEN
                        ),
                      }}
                    />
                    {relationTypeLabel(type, t)} · {list.length}
                  </summary>
                  <ul className="attack-path-rel-list">
                    {list.map((relation, idx) => {
                      const src =
                        hostByID.get(relation.src_host_id) ??
                        `#${relation.src_host_id}`;
                      const dst =
                        hostByID.get(relation.dst_host_id) ??
                        `#${relation.dst_host_id}`;

                      return (
                        <li key={`${type}-${idx}`}>
                          <div className="attack-path-rel-main">
                            <span className="attack-path-rel-edge">
                              {src} <ChevronRight aria-hidden size={12} /> {dst}
                            </span>
                            <div className="attack-path-rel-meter">
                              <ProbabilityBar
                                ariaLabel={t(
                                  'risk.attackPath.strengthThreshold'
                                )}
                                value={relation.strength}
                              />
                              <span className="attack-path-rel-strength">
                                {relation.strength.toFixed(2)}
                              </span>
                            </div>
                            {relation.evidence != null &&
                              Object.keys(relation.evidence).length > 0 && (
                                <dl className="attack-path-rel-evidence">
                                  {Object.entries(relation.evidence).map(
                                    ([key, value]) => (
                                      <div key={key}>
                                        <dt>
                                          {t(
                                            `risk.attackPath.evidence.${key}`,
                                            { defaultValue: key }
                                          )}
                                        </dt>
                                        <dd>{String(value)}</dd>
                                      </div>
                                    )
                                  )}
                                </dl>
                              )}
                          </div>
                          {!dst.startsWith('#') && (
                            <Link
                              className="attack-path-rel-open"
                              to={`/hosts/${encodeURIComponent(dst)}`}
                            >
                              {t('risk.attackPath.openHost')}
                            </Link>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </details>
              ))
            )}
          </aside>
        </div>
      )}
    </section>
  );
}
