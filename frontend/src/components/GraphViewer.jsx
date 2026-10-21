/**
 * components/GraphViewer.jsx — CVE / dependency knowledge graph
 *
 * Renders GET /api/investigations/:invId/graph as an interactive force graph.
 * Node types: repo | package | file | cve. Severity tints CVE/package nodes.
 *
 * Props:
 *   invId: string
 *   graph?: { nodes, edges }   — pass directly, or omit to fetch
 */

import { useEffect, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { getGraph } from "../services/api";

const TYPE_COLOR = {
  repo: "#14161d",
  package: "#2563eb",
  file: "#9197a6",
  cve: "#dc2626",
};
const SEVERITY_COLOR = {
  high: "#dc2626",
  medium: "#d97706",
  warning: "#7c3aed",
};

function colorFor(node) {
  if (node.severity && SEVERITY_COLOR[node.severity]) return SEVERITY_COLOR[node.severity];
  return TYPE_COLOR[node.type] ?? "#9197a6";
}

export default function GraphViewer({ invId, graph: propGraph }) {
  const [graph, setGraph] = useState(propGraph ?? null);
  const wrapRef = useRef(null);
  const [size, setSize] = useState({ w: 600, h: 360 });

  useEffect(() => {
    if (propGraph) { setGraph(propGraph); return; }
    getGraph(invId).then(setGraph).catch(console.error);
  }, [invId, propGraph]);

  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver(([entry]) => {
      setSize({ w: entry.contentRect.width, h: 360 });
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, [graph]);

  if (!graph) return <p className="gv-msg">Loading graph…</p>;
  if (!graph.nodes?.length) return <p className="gv-msg">No graph data available.</p>;

  // react-force-graph wants {nodes, links} with source/target ids
  const data = {
    nodes: graph.nodes.map((n) => ({ ...n })),
    links: (graph.edges ?? []).map((e) => ({ source: e.source, target: e.target, label: e.label })),
  };

  return (
    <div className="gv">
      <div className="gv-legend">
        {Object.entries(TYPE_COLOR).map(([type, c]) => (
          <span key={type} className="gv-leg">
            <span className="gv-dot" style={{ background: c }} /> {type}
          </span>
        ))}
        <span className="gv-hint">drag to explore · scroll to zoom</span>
      </div>
      <div ref={wrapRef} className="gv-canvas">
        <ForceGraph2D
          graphData={data}
          width={size.w}
          height={size.h}
          backgroundColor="rgba(0,0,0,0)"
          linkColor={() => "rgba(89,96,111,0.30)"}
          linkDirectionalArrowLength={3}
          linkDirectionalArrowRelPos={0.85}
          nodeRelSize={5}
          cooldownTicks={80}
          nodeCanvasObject={(node, ctx, scale) => {
            const r = (node.type === "repo" ? 7 : node.type === "cve" ? 6 : 5);
            ctx.beginPath();
            ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
            ctx.fillStyle = colorFor(node);
            ctx.fill();
            const fontSize = Math.max(10 / scale, 2.5);
            ctx.font = `500 ${fontSize}px JetBrains Mono, monospace`;
            ctx.fillStyle = "#59606f";
            ctx.textAlign = "center";
            ctx.textBaseline = "top";
            if (scale > 0.6) ctx.fillText(node.label, node.x, node.y + r + 1.5);
          }}
        />
      </div>
      <style>{`
        .gv-msg { font-family: var(--mono); font-size: 13px; color: var(--text-faint); padding: 16px 4px; }
        .gv { width: 100%; }
        .gv-legend {
          display: flex; flex-wrap: wrap; align-items: center; gap: 14px; margin-bottom: 8px;
        }
        .gv-leg {
          display: inline-flex; align-items: center; gap: 6px;
          font-family: var(--mono); font-size: 11px; color: var(--text-dim);
        }
        .gv-dot { width: 8px; height: 8px; border-radius: 99px; }
        .gv-hint { margin-left: auto; font-family: var(--mono); font-size: 10px; color: var(--text-faint); }
        .gv-canvas {
          width: 100%; height: 360px; border: 1px solid var(--border);
          border-radius: var(--radius); overflow: hidden; background: var(--bg-grid);
        }
      `}</style>
    </div>
  );
}
