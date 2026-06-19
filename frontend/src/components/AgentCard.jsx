/**
 * components/AgentCard.jsx — Individual agent result card
 *
 * Props:
 *   result: {
 *     agent, verdict, confidence (0..1), duration_ms, evidence[], metadata{}
 *   }
 *   active?: boolean   — currently-running highlight (War Room)
 *
 * Verdicts: confirmed | rejected | inconclusive
 *           counter_evidence_found | no_counter_evidence (Challenger)
 */

import { agentMeta } from "../agents";

const VERDICT = {
  confirmed:              { label: "Confirmed",        tone: "var(--ok)" },
  no_counter_evidence:    { label: "No counter-ev.",   tone: "var(--ok)" },
  counter_evidence_found: { label: "Counter-evidence", tone: "var(--warn)" },
  rejected:               { label: "Rejected",         tone: "var(--bad)" },
  inconclusive:           { label: "Inconclusive",     tone: "var(--text-dim)" },
};

export default function AgentCard({ result, active = false }) {
  const meta = agentMeta(result.agent);
  const v = VERDICT[result.verdict] ?? { label: result.verdict, tone: "var(--text-dim)" };
  const conf = result.confidence ?? 0;
  const pct = Math.round(conf * 100);

  return (
    <div
      className="agent-card"
      style={{
        borderColor: active ? meta.color : "var(--border)",
        boxShadow: active ? `0 0 0 1px ${meta.color}, 0 0 22px -8px ${meta.color}` : "none",
      }}
    >
      <div className="agent-card-head">
        <span className="agent-glyph" style={{ color: meta.color }}>{meta.icon}</span>
        <span className="agent-card-name">{meta.label}</span>
        <span className="agent-card-verdict" style={{ color: v.tone }}>{v.label}</span>
      </div>

      <div className="agent-card-conf">
        <div className="conf-track">
          <div className="conf-fill" style={{ width: `${pct}%`, background: meta.color }} />
        </div>
        <span className="conf-num">{pct}%</span>
      </div>

      <div className="agent-card-foot">
        {result.metadata?.status && (
          <span className="chip" style={{ color: v.tone }}>{result.metadata.status}</span>
        )}
        {result.metadata?.attempts > 1 && (
          <span className="chip">{result.metadata.attempts} attempts</span>
        )}
        {typeof result.duration_ms === "number" && (
          <span className="agent-card-dur">{(result.duration_ms / 1000).toFixed(1)}s</span>
        )}
      </div>

      {result.evidence?.[0]?.detail && (
        <p className="agent-card-evidence">{result.evidence[0].detail}</p>
      )}

      <style>{`
        .agent-card {
          background: var(--panel);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          padding: 14px 15px;
          transition: border-color .18s, box-shadow .18s;
        }
        .agent-card-head {
          display: flex; align-items: center; gap: 9px; margin-bottom: 12px;
        }
        .agent-glyph { font-size: 16px; line-height: 1; }
        .agent-card-name {
          font-family: var(--display); font-weight: 600; font-size: 14px;
          color: var(--text); flex: 1;
        }
        .agent-card-verdict {
          font-family: var(--mono); font-size: 11px; font-weight: 500;
          letter-spacing: .3px;
        }
        .agent-card-conf { display: flex; align-items: center; gap: 10px; }
        .conf-track {
          flex: 1; height: 6px; border-radius: 99px;
          background: var(--bg-grid); overflow: hidden;
        }
        .conf-fill { height: 100%; border-radius: 99px; transition: width .5s ease; }
        .conf-num {
          font-family: var(--mono); font-size: 12px; color: var(--text-dim);
          min-width: 36px; text-align: right;
        }
        .agent-card-foot {
          display: flex; align-items: center; gap: 8px; margin-top: 11px;
          min-height: 18px;
        }
        .chip {
          font-family: var(--mono); font-size: 10px; letter-spacing: .5px;
          padding: 2px 7px; border-radius: 5px; background: var(--neutral-bg);
          color: var(--text-dim);
        }
        .agent-card-dur {
          margin-left: auto; font-family: var(--mono); font-size: 11px;
          color: var(--text-faint);
        }
        .agent-card-evidence {
          margin-top: 10px; font-size: 12px; line-height: 1.5;
          color: var(--text-dim);
          border-top: 1px solid var(--border); padding-top: 10px;
        }
      `}</style>
    </div>
  );
}
