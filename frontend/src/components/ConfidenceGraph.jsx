/**
 * components/ConfidenceGraph.jsx — Confidence evolution chart
 * Owner: Harsh
 *
 * Props:
 *   invId: string         — investigation ID (used if fetching internally)
 *   snapshots?: Array<{ timestamp, fused, per_agent: {} }>
 *                         — pass snapshots directly or leave null to fetch
 *
 * Chart library: recharts (already available via CDN in Vite) or Chart.js — your choice.
 */

import { useEffect, useState } from "react";
import { getConfidenceEvolution } from "../services/api";

export default function ConfidenceGraph({ invId, snapshots: propSnapshots }) {
  const [snapshots, setSnapshots] = useState(propSnapshots ?? []);

  useEffect(() => {
    if (propSnapshots) return; // use parent-provided data
    getConfidenceEvolution(invId).then(setSnapshots).catch(console.error);
  }, [invId]);

  if (snapshots.length === 0) return <p>No confidence data yet…</p>;

  // TODO: Harsh — replace with a proper chart
  return (
    <pre>
      {snapshots.map((s) => `${s.timestamp}: fused=${s.fused?.toFixed(2)}`).join("\n")}
    </pre>
  );
}
