/**
 * components/GraphViewer.jsx — CVE / dependency knowledge graph
 * Owner: Harsh
 *
 * Props:
 *   invId: string
 *
 * Fetches GET /api/investigations/:invId/graph
 * Response shape: { nodes: [{id, label, type}], edges: [{source, target, label}] }
 *
 * Suggested libs: react-force-graph, cytoscape.js, vis-network
 */

import { useEffect, useState } from "react";
import { getGraph } from "../services/api";

export default function GraphViewer({ invId }) {
  const [graph, setGraph] = useState(null);

  useEffect(() => {
    getGraph(invId).then(setGraph).catch(console.error);
  }, [invId]);

  if (!graph) return <p>Loading graph…</p>;
  if (!graph.nodes?.length) return <p>No graph data available.</p>;

  // TODO: Harsh — replace with a real graph renderer
  return (
    <div>
      <p>{graph.nodes.length} nodes, {graph.edges?.length ?? 0} edges</p>
      <pre>{JSON.stringify(graph, null, 2)}</pre>
    </div>
  );
}
