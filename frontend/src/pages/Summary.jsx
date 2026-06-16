/**
 * pages/Summary.jsx — Final investigation report
 * Owner: Harsh
 *
 * Fetches full summary from GET /api/investigations/:inv_id/summary
 * Shows: agent results, decision log, confidence evolution, graph.
 */

import { useEffect, useState } from "react";
import { getSummary } from "../services/api";
import AgentCard from "../components/AgentCard";
import ConfidenceGraph from "../components/ConfidenceGraph";
import GraphViewer from "../components/GraphViewer";

function getInvId() {
  return window.location.pathname.split("/").at(-1);
}

export default function Summary() {
  const invId = getInvId();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getSummary(invId)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [invId]);

  if (error) return <p>Error: {error}</p>;
  if (!data) return <p>Loading summary...</p>;

  const { investigation, agent_results, decision_log, confidence_evolution } = data;

  return (
    <div>
      {/* TODO: Harsh — build the summary report UI here */}
      <h1>Investigation Report — {investigation.inv_id}</h1>
      <p>Repo: {investigation.repo_path}</p>
      <p>Status: {investigation.status}</p>
      <p>Fused Confidence: {investigation.fused_confidence?.toFixed(2) ?? "—"}</p>

      <h2>Agent Results</h2>
      {agent_results.map((r) => (
        <AgentCard key={r.agent} result={r} />
      ))}

      <h2>Confidence Evolution</h2>
      <ConfidenceGraph invId={invId} snapshots={confidence_evolution} />

      <h2>Knowledge Graph</h2>
      <GraphViewer invId={invId} />

      <h2>Decision Log</h2>
      <pre>{JSON.stringify(decision_log, null, 2)}</pre>
    </div>
  );
}
