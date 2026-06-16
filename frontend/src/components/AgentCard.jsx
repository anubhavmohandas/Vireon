/**
 * components/AgentCard.jsx — Individual agent result card
 * Owner: Harsh
 *
 * Props:
 *   result: {
 *     agent: string
 *     verdict: string          — e.g. "confirmed" | "counter_evidence_found"
 *     confidence: number       — 0..1
 *     duration_ms: number
 *     evidence: Array<{}>
 *     metadata: {}
 *   }
 *
 * Challenger verdicts: "counter_evidence_found" | "no_counter_evidence" | "inconclusive"
 * Standard verdicts:   "confirmed" | "rejected" | "inconclusive"
 */

const VERDICT_COLOR = {
  confirmed: "#d4edda",
  rejected: "#f8d7da",
  counter_evidence_found: "#fff3cd",
  no_counter_evidence: "#d4edda",
  inconclusive: "#e2e3e5",
};

export default function AgentCard({ result }) {
  const bg = VERDICT_COLOR[result.verdict] ?? "#fff";

  return (
    <div style={{ background: bg, margin: "8px 0", padding: "8px", borderRadius: 4 }}>
      {/* TODO: Harsh — style this properly */}
      <strong>{result.agent}</strong>
      <span> verdict={result.verdict}</span>
      <span> conf={result.confidence?.toFixed(2)}</span>
      <span> ({result.duration_ms}ms)</span>
      {result.metadata?.status && <span> [{result.metadata.status}]</span>}
    </div>
  );
}
