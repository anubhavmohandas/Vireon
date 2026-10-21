/**
 * components/StatusBadge.jsx — Investigation status pill
 *
 * Props:
 *   status: "running" | "completed" | "aborted" | "failed" | "pending"
 */

const MAP = {
  running:   { label: "Running",   color: "var(--violet)", dot: true },
  completed: { label: "Completed", color: "var(--ok)",     dot: false },
  aborted:   { label: "Aborted",   color: "var(--warn)",   dot: false },
  failed:    { label: "Failed",    color: "var(--bad)",    dot: false },
  pending:   { label: "Pending",   color: "var(--text-dim)", dot: false },
};

export default function StatusBadge({ status }) {
  const s = MAP[status] ?? MAP.pending;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        padding: "4px 12px",
        borderRadius: 99,
        fontFamily: "var(--mono)",
        fontSize: 12,
        fontWeight: 500,
        letterSpacing: 0.5,
        color: s.color,
        border: `1px solid ${s.color}`,
        background: "color-mix(in srgb, currentColor 8%, transparent)",
      }}
    >
      {s.dot && <span className="pulse-dot" style={{ background: s.color }} />}
      {s.label}
      <style>{`
        .pulse-dot {
          width: 7px; height: 7px; border-radius: 99px;
          animation: pulse 1.4s ease-in-out infinite;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.4; transform: scale(0.7); }
        }
      `}</style>
    </span>
  );
}
