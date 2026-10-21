/**
 * pages/Summary.jsx — Final investigation report.
 *
 * One call to GET /api/investigations/:invId/summary returns everything:
 * investigation metadata, agent results, decision log, confidence evolution.
 * The knowledge graph is fetched separately by GraphViewer.
 */

import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { getSummary } from "../services/api";
import AgentCard from "../components/AgentCard";
import ConfidenceGraph from "../components/ConfidenceGraph";
import GraphViewer from "../components/GraphViewer";
import Vulnerabilities from "../components/Vulnerabilities";
import StatusBadge from "../components/StatusBadge";
import { AGENT_ORDER, agentMeta } from "../agents";

const ACTION_TONE = {
  objection: "var(--warn)",
  reject: "var(--bad)",
  approve: "var(--ok)",
  draft_saved: "var(--violet)",
};

export default function Summary() {
  const { invId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    getSummary(invId).then(setData).catch((e) => setError(e.message));
  }, [invId]);

  if (error) {
    return (
      <Centered>
        <p className="state-msg">Couldn't load the report: {error}</p>
        <Link to="/">← Start a new investigation</Link>
      </Centered>
    );
  }
  if (!data) return <Centered><p className="state-msg">Loading summary…</p></Centered>;

  const { investigation, agent_results, decision_log, confidence_evolution, vulnerabilities } = data;

  // Order agent cards by pipeline order.
  const byAgent = Object.fromEntries(agent_results.map((r) => [r.agent, r]));
  const orderedResults = AGENT_ORDER.map((a) => byAgent[a]).filter(Boolean);

  const prResult = byAgent.pr;
  const prPath = prResult?.metadata?.pr_path;

  const vulns = vulnerabilities ?? [];
  const patchedCount = vulns.filter((v) => v.status === "patched").length;

  return (
    <>
      <header className="topbar">
        <div className="shell topbar-inner">
          <Link to="/" className="brand"><span className="spark">⚡</span> Vireon</Link>
          <span className="topbar-meta">{investigation.inv_id}</span>
        </div>
      </header>

      <main className="shell summary">
        <section className="sum-head">
          <div>
            <p className="eyebrow">Investigation report</p>
            <h1 className="sum-id">{investigation.inv_id}</h1>
            <p className="sum-repo">{investigation.repo_path}</p>
          </div>
          <StatusBadge status={investigation.status} />
        </section>

        <section className="sum-stats">
          <Stat label="Fused confidence"
            value={investigation.fused_confidence != null
              ? `${Math.round(investigation.fused_confidence * 100)}%` : "—"}
            tone={confTone(investigation.fused_confidence)} />
          <Stat label="Vulnerabilities" value={vulns.length} />
          <Stat label="Patched" value={patchedCount} tone="var(--ok)" />
          <Stat label="Pull request"
            value={prPath ? "Draft saved" : (prResult?.metadata?.pr_url ? "Opened" : "—")} />
        </section>

        {prPath && (
          <div className="pr-banner">
            No GitHub token was configured, so the full pull request was written to{" "}
            <code>{prPath}</code>. Add <code>GITHUB_TOKEN</code> and{" "}
            <code>GITHUB_REPO</code> to open it directly next time.
          </div>
        )}

        <section className="sum-block">
          <h2 className="sum-h2">Vulnerabilities</h2>
          <Vulnerabilities items={vulns} />
        </section>

        <section className="sum-block">
          <h2 className="sum-h2">Patch &amp; verification</h2>
          <div className="outcome-row">
            <OutcomeStep
              label="Patch" icon={agentMeta("remediation").icon}
              color={agentMeta("remediation").color}
              value={byAgent.remediation ? "Generated" : "—"}
              note={byAgent.remediation?.metadata?.attempts > 1
                ? `${byAgent.remediation.metadata.attempts} attempts` : "1st attempt"}
              ok={!!byAgent.remediation} />
            <OutcomeStep
              label="Compliance" icon={agentMeta("compliance").icon}
              color={agentMeta("compliance").color}
              value={byAgent.compliance?.metadata?.status === "APPROVED" ? "Approved"
                : (byAgent.compliance ? byAgent.compliance.verdict : "—")}
              note={byAgent.compliance?.metadata?.rejections
                ? `${byAgent.compliance.metadata.rejections} rejection(s)` : "policy gate"}
              ok={byAgent.compliance?.metadata?.status === "APPROVED"} />
            <OutcomeStep
              label="Verification" icon={agentMeta("verification").icon}
              color={agentMeta("verification").color}
              value={byAgent.verification?.verdict === "confirmed" ? "Passed"
                : (byAgent.verification ? "Failed" : "—")}
              note="tests + re-scan"
              ok={byAgent.verification?.verdict === "confirmed"} />
            <OutcomeStep
              label="Pull request" icon={agentMeta("pr").icon}
              color={agentMeta("pr").color}
              value={prPath ? "Draft saved" : (prResult?.metadata?.pr_url ? "Opened" : "—")}
              note={prPath ? "no token" : (prResult?.metadata?.pr_url ? "on GitHub" : "")}
              ok={!!prResult} />
          </div>
        </section>

        <section className="sum-block">
          <h2 className="sum-h2">Agent results</h2>
          <div className="card-grid">
            {orderedResults.map((r) => <AgentCard key={r.agent} result={r} />)}
          </div>
        </section>

        <div className="sum-two">
          <section className="sum-block panel sum-panel">
            <h2 className="sum-h2">Confidence evolution</h2>
            <ConfidenceGraph invId={invId} snapshots={confidence_evolution} />
          </section>
          <section className="sum-block panel sum-panel">
            <h2 className="sum-h2">Decision log</h2>
            <ol className="decisions">
              {decision_log.map((d) => (
                <li key={d.id} className="decision">
                  <span className="dec-rail" style={{ background: agentMeta(d.agent).color }} />
                  <div className="dec-head">
                    <span className="dec-agent" style={{ color: agentMeta(d.agent).color }}>
                      {agentMeta(d.agent).label}
                    </span>
                    <span className="dec-action" style={{ color: ACTION_TONE[d.action] ?? "var(--text-dim)" }}>
                      {d.action.replace(/_/g, " ")}
                    </span>
                  </div>
                  {d.reason && <p className="dec-reason">{d.reason}</p>}
                </li>
              ))}
            </ol>
          </section>
        </div>

        <section className="sum-block panel sum-panel">
          <h2 className="sum-h2">Knowledge graph</h2>
          <GraphViewer invId={invId} />
        </section>

        <div className="sum-foot">
          <Link to="/" className="sum-again">← Run another investigation</Link>
        </div>
      </main>

      <style>{`
        .summary { padding: 30px 0 80px; }
        .sum-head {
          display: flex; justify-content: space-between; align-items: flex-start;
          gap: 16px; margin-bottom: 24px;
        }
        .sum-id {
          font-family: var(--mono); font-weight: 700; font-size: 28px;
          letter-spacing: -.5px; margin: 6px 0 4px;
        }
        .sum-repo { font-family: var(--mono); font-size: 13px; color: var(--text-dim); }
        .sum-stats {
          display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 22px;
        }
        .stat {
          background: var(--panel); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 16px 18px;
        }
        .stat-val {
          font-family: var(--display); font-weight: 700; font-size: 26px; letter-spacing: -.5px;
        }
        .stat-label {
          font-family: var(--mono); font-size: 10px; letter-spacing: 1px;
          text-transform: uppercase; color: var(--text-faint); margin-top: 5px;
        }
        .pr-banner {
          background: var(--violet-glow); border: 1px solid var(--violet-dim);
          border-radius: var(--radius); padding: 14px 18px; font-size: 14px;
          line-height: 1.6; color: var(--text-dim); margin-bottom: 26px;
        }
        .pr-banner code {
          font-family: var(--mono); font-size: 12px; color: var(--violet);
          background: var(--violet-glow); padding: 1px 6px; border-radius: 4px;
        }
        .sum-block { margin-bottom: 26px; }
        .sum-h2 {
          font-family: var(--display); font-weight: 600; font-size: 16px;
          margin-bottom: 14px;
        }
        .outcome-row {
          display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
        }
        .outcome {
          background: var(--panel); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 13px 15px;
          display: flex; flex-direction: column; gap: 6px;
        }
        .outcome-head {
          display: flex; align-items: center; gap: 8px;
          font-family: var(--mono); font-size: 10px; letter-spacing: 1px;
          text-transform: uppercase; color: var(--text-faint);
        }
        .outcome-val {
          display: flex; align-items: center; gap: 7px;
          font-family: var(--display); font-weight: 600; font-size: 16px; color: var(--text);
        }
        .outcome-check { font-family: var(--mono); font-size: 13px; }
        .outcome-note { font-family: var(--mono); font-size: 11px; color: var(--text-faint); }
        @media (max-width: 720px) {
          .outcome-row { grid-template-columns: repeat(2, 1fr); }
        }
        .card-grid {
          display: grid; grid-template-columns: repeat(auto-fill, minmax(255px, 1fr)); gap: 12px;
        }
        .sum-two { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .sum-panel { padding: 18px 20px; }

        .decisions { list-style: none; display: flex; flex-direction: column; gap: 4px; }
        .decision { position: relative; padding: 10px 4px 12px 16px; border-bottom: 1px solid var(--border); }
        .decision:last-child { border-bottom: none; }
        .dec-rail { position: absolute; left: 0; top: 12px; bottom: 12px; width: 3px; border-radius: 99px; }
        .dec-head { display: flex; align-items: baseline; gap: 10px; }
        .dec-agent { font-family: var(--display); font-weight: 600; font-size: 13px; }
        .dec-action {
          font-family: var(--mono); font-size: 11px; text-transform: uppercase; letter-spacing: .5px;
        }
        .dec-reason { font-size: 13px; line-height: 1.5; color: var(--text-dim); margin-top: 4px; }

        .sum-foot { margin-top: 12px; }
        .sum-again { font-family: var(--mono); font-size: 13px; }

        .state-msg { font-family: var(--mono); font-size: 14px; color: var(--text-dim); margin-bottom: 12px; }

        @media (max-width: 880px) {
          .sum-stats { grid-template-columns: repeat(2, 1fr); }
          .sum-two { grid-template-columns: 1fr; }
        }
      `}</style>
    </>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className="stat">
      <div className="stat-val" style={tone ? { color: tone } : undefined}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function OutcomeStep({ label, icon, color, value, note, ok }) {
  return (
    <div className="outcome">
      <div className="outcome-head">
        <span style={{ color }}>{icon}</span> {label}
      </div>
      <div className="outcome-val">
        {value}
        <span className="outcome-check" style={{ color: ok ? "var(--ok)" : "var(--text-faint)" }}>
          {ok ? "✓" : ""}
        </span>
      </div>
      {note && <div className="outcome-note">{note}</div>}
    </div>
  );
}

function Centered({ children }) {
  return (
    <main className="shell" style={{ display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center", minHeight: "100vh", gap: 8 }}>
      {children}
    </main>
  );
}

function confTone(c) {
  if (c == null) return "var(--text-faint)";
  if (c < 0.3) return "var(--bad)";
  if (c < 0.6) return "var(--warn)";
  return "var(--ok)";
}
