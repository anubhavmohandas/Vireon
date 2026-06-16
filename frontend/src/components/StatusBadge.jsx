/**
 * components/StatusBadge.jsx — Investigation status pill
 * Owner: Harsh
 *
 * Props:
 *   status: "running" | "completed" | "aborted" | "pending"
 */

const COLOR = {
  running: { bg: "#cfe2ff", text: "#084298" },
  completed: { bg: "#d1e7dd", text: "#0f5132" },
  aborted: { bg: "#f8d7da", text: "#842029" },
  pending: { bg: "#e2e3e5", text: "#41464b" },
};

export default function StatusBadge({ status }) {
  const { bg, text } = COLOR[status] ?? COLOR.pending;
  return (
    <span style={{ background: bg, color: text, padding: "2px 10px", borderRadius: 99 }}>
      {status ?? "unknown"}
    </span>
  );
}
