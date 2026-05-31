import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';

import { useTheme } from '@/theme/ThemeProvider';
import { hostIPLiteral } from '@helpers/hostPathFromScanTarget';
import type { PivotEdge, PivotNode, PivotResponse } from '@/types/pivot';

import { nodeColor, nodeHaloColor, pivotGraphTheme, pivotNodeLabel } from './pivotHelpers';

type GraphNode = PivotNode & { x?: number; y?: number };

type GraphData = {
  nodes: GraphNode[];
  links: Array<PivotEdge & { source: string; target: string }>;
};

type PivotGraphProps = {
  data: PivotResponse;
};

export function PivotGraph({ data }: PivotGraphProps) {
  const navigate = useNavigate();
  const { theme } = useTheme();
  const wrapRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 640, height: 480 });
  const palette = useMemo(() => pivotGraphTheme(theme), [theme]);

  useEffect(() => {
    const element = wrapRef.current;

    if (!element) {
      return;
    }

    const sync = () => {
      setSize({
        width: Math.max(element.clientWidth, 280),
        height: Math.max(element.clientHeight, 320),
      });
    };

    sync();

    const observer = new ResizeObserver(sync);

    observer.observe(element);

    return () => {
      observer.disconnect();
    };
  }, []);

  const graphData = useMemo<GraphData>(
    () => ({
      nodes: data.nodes.map((node) => ({ ...node })),
      links: data.edges.map((edge) => ({ ...edge })),
    }),
    [data]
  );

  const handleNodeClick = useCallback(
    (node: GraphNode) => {
      const ip = hostIPLiteral(node.ip);

      if (!ip) {
        return;
      }

      navigate(`/hosts/${encodeURIComponent(ip)}`);
    },
    [navigate]
  );

  return (
    <div className="pivot-graph-wrap" ref={wrapRef}>
      <ForceGraph2D
        backgroundColor={palette.background}
        cooldownTicks={80}
        graphData={graphData}
        height={size.height}
        linkColor={() => palette.link}
        linkDirectionalArrowLength={3.5}
        linkDirectionalArrowRelPos={1}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const graphNode = node as GraphNode;
          const label = pivotNodeLabel(graphNode);
          const fontSize = Math.max(10 / globalScale, 3);
          const radius = graphNode.kind === 'artifact' ? 8 : graphNode.kind === 'host' ? 6 : 5;
          const halo = nodeHaloColor(graphNode);
          const x = graphNode.x ?? 0;
          const y = graphNode.y ?? 0;

          if (halo) {
            ctx.beginPath();
            ctx.arc(x, y, radius + 5, 0, 2 * Math.PI);
            ctx.fillStyle = halo;
            ctx.fill();
          }

          ctx.beginPath();
          ctx.arc(x, y, radius, 0, 2 * Math.PI);
          ctx.fillStyle = nodeColor(graphNode, palette);
          ctx.fill();

          if (graphNode.kind === 'artifact') {
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.35)';
            ctx.lineWidth = 1.5 / globalScale;
            ctx.stroke();
          }

          ctx.font = `${String(fontSize)}px var(--font-sans, sans-serif)`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          ctx.fillStyle = palette.label;
          ctx.fillText(label, x, y + radius + 3);
        }}
        nodePointerAreaPaint={(node, color, ctx) => {
          const graphNode = node as GraphNode;
          const radius = graphNode.kind === 'artifact' ? 12 : graphNode.ip ? 10 : 6;

          ctx.beginPath();
          ctx.arc(graphNode.x ?? 0, graphNode.y ?? 0, radius, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          ctx.fill();
        }}
        onNodeClick={(node) => {
          handleNodeClick(node as GraphNode);
        }}
        width={size.width}
      />
    </div>
  );
}
