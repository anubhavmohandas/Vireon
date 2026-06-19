/**
 * pages/Landing.jsx — Hero, agent pipeline, and scan trigger.
 *
 * Repo path + lookback window -> POST /api/scan -> /war-room/:inv_id
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { startScan } from "../services/api";
import { AGENT_ORDER, agentMeta } from "../agents";

const PHASES = [
  { n: 1, name: "Evidence", agents: ["threat", "static"] },
  { n: 2, name: "Triage", agents: ["exploitability"] },
  { n: 3, name: "Debate", agents: ["challenger"] },
  { n: 4, name: "Patch loop", agents: ["remediation", "compliance"] },
  { n: 5, name: "Verify + ship", agents: ["verification", "pr"] },
];

export default function Landing() {
  const navigate = useNavigate();
  const [repoPath, setRepoPath] = useState("");
  const [days, setDays] = useState(7);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleScan(e) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const { inv_id } = await startScan(repoPath, days);
      navigate(`/war-room/${inv_id}`);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <>
      <header className="topbar">
        <div className="shell topbar-inner">
          <span className="brand"><span className="spark">⚡</span> Vireon</span>
          <span className="topbar-meta">8 agents · 0 humans</span>
        </div>
      </header>

      <main className="shell landing">
        <section className="hero">
          <p className="eyebrow">Autonomous security investigation</p>
          <h1 className="hero-title">
            Point it at a repo.<br />
            <span className="hero-accent">Eight agents argue.</span><br />
            Walk away with a patch.
          </h1>
          <p className="hero-sub">
            Vireon fetches real CVEs, runs Semgrep, and lets an LLM red team try to
            disprove every finding before it writes a fix, checks the fix against
            policy, re-scans, and opens a pull request. Every decision is logged
            with the agent, timestamp, confidence, and reasoning.
          </p>

          <form className="scan-form" onSubmit={handleScan}>
            <div className="scan-field">
              <label htmlFor="repo">Repository path</label>
              <input
                id="repo"
                value={repoPath}
                onChange={(e) => setRepoPath(e.target.value)}
                placeholder="/path/to/your/repo"
                required
                autoFocus
              />
            </div>
            <div className="scan-field scan-field-sm">
              <label htmlFor="days">CVE lookback</label>
              <div className="days-input">
                <input
                  id="days" type="number" value={days} min={1} max={90}
                  onChange={(e) => setDays(Number(e.target.value))}
                />
                <span>days</span>
              </div>
            </div>
            <button type="submit" className="scan-btn" disabled={loading}>
              {loading ? "Starting…" : "Start investigation"}
            </button>
          </form>
          {error && <p className="scan-error">Couldn't start the scan: {error}</p>}
        </section>

        <section className="pipeline-section">
          <p className="eyebrow">The pipeline</p>
          <div className="pipeline">
            {PHASES.map((phase, pi) => (
              <div key={phase.n} className="phase">
                <div className="phase-head">
                  <span className="phase-n">{String(phase.n).padStart(2, "0")}</span>
                  <span className="phase-name">{phase.name}</span>
                </div>
                <div className="phase-agents">
                  {phase.agents.map((a) => {
                    const m = agentMeta(a);
                    return (
                      <div key={a} className="phase-agent" style={{ "--c": m.color }}>
                        <span className="pa-glyph">{m.icon}</span>
                        <span className="pa-name">{m.label}</span>
                      </div>
                    );
                  })}
                </div>
                {pi < PHASES.length - 1 && <span className="phase-arrow">→</span>}
              </div>
            ))}
          </div>
          <p className="pipeline-note">
            Phase 3 is the point. The Challenger has a negative weight in the
            confidence fusion — if it can't find a mitigation, the case against a
            finding gets <em>stronger</em>. Fused confidence below 0.30 aborts the
            run, so there are no false-alarm pull requests.
          </p>
        </section>
      </main>

      <style>{`
        .landing { padding-bottom: 80px; }
        .hero { padding: 72px 0 56px; max-width: 720px; }
        .hero-title {
          font-family: var(--display); font-weight: 700; font-size: clamp(34px, 5.5vw, 56px);
          line-height: 1.04; letter-spacing: -1px; margin: 14px 0 22px;
        }
        .hero-accent { color: var(--violet); }
        .hero-sub {
          font-size: 16px; line-height: 1.65; color: var(--text-dim); max-width: 600px;
        }
        .scan-form {
          display: flex; gap: 12px; align-items: flex-end; margin-top: 34px; flex-wrap: wrap;
        }
        .scan-field { display: flex; flex-direction: column; gap: 7px; flex: 1; min-width: 220px; }
        .scan-field-sm { flex: 0 0 auto; min-width: 0; }
        .scan-field label {
          font-family: var(--mono); font-size: 11px; letter-spacing: 1px;
          text-transform: uppercase; color: var(--text-faint);
        }
        .scan-field input {
          background: var(--panel); border: 1px solid var(--border);
          border-radius: var(--radius-sm); color: var(--text);
          font-family: var(--mono); font-size: 14px; padding: 12px 14px;
          transition: border-color .15s;
        }
        .scan-field input:focus { outline: none; border-color: var(--violet); }
        .days-input { display: flex; align-items: center; gap: 8px; }
        .days-input input { width: 78px; }
        .days-input span { font-family: var(--mono); font-size: 13px; color: var(--text-faint); }
        .scan-btn {
          background: var(--violet); color: #ffffff; border: none;
          border-radius: var(--radius-sm); font-weight: 600; font-size: 14px;
          padding: 13px 22px; transition: filter .15s, transform .05s;
        }
        .scan-btn:hover:not(:disabled) { filter: brightness(1.08); }
        .scan-btn:active:not(:disabled) { transform: translateY(1px); }
        .scan-btn:disabled { opacity: .6; cursor: not-allowed; }
        .scan-error { color: var(--bad); font-family: var(--mono); font-size: 13px; margin-top: 14px; }

        .pipeline-section { border-top: 1px solid var(--border); padding-top: 40px; }
        .pipeline {
          display: flex; flex-wrap: wrap; gap: 10px; align-items: stretch; margin: 18px 0 22px;
        }
        .phase { position: relative; display: flex; flex-direction: column; gap: 8px; }
        .phase-head { display: flex; align-items: baseline; gap: 8px; }
        .phase-n { font-family: var(--mono); font-size: 11px; color: var(--text-faint); }
        .phase-name {
          font-family: var(--display); font-weight: 600; font-size: 13px; color: var(--text-dim);
        }
        .phase-agents { display: flex; flex-direction: column; gap: 6px; }
        .phase-agent {
          display: flex; align-items: center; gap: 8px;
          background: var(--panel); border: 1px solid var(--border);
          border-left: 2px solid var(--c);
          border-radius: var(--radius-sm); padding: 9px 12px; min-width: 150px;
        }
        .pa-glyph { color: var(--c); font-size: 14px; }
        .pa-name { font-family: var(--display); font-size: 13px; font-weight: 500; }
        .phase-arrow {
          position: absolute; right: -11px; top: 50%; color: var(--border-bright); font-size: 16px;
        }
        .pipeline-note {
          font-size: 14px; line-height: 1.65; color: var(--text-dim); max-width: 640px;
        }
        .pipeline-note em { color: var(--text); font-style: italic; }

        @media (max-width: 760px) {
          .phase-arrow { display: none; }
          .pipeline { flex-direction: column; }
        }
      `}</style>
    </>
  );
}
