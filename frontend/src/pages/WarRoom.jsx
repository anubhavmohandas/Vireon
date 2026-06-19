/**
 * pages/WarRoom.jsx — Live investigation dashboard.
 *
 * Polls /status and /timeline every 2s. Shows the confidence gauge, the agent
 * card grid (highlighting whoever is currently running), and the live event
 * feed. Redirects to /summary/:invId shortly after status === "completed".
 */

import { useEffect, useRef, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { getStatus, getTimeline, getConfidenceEvolution } from "../services/api";
import Timeline from "../components/Timeline";
import ConfidenceGraph from "../components/ConfidenceGraph";
import StatusBadge from "../components/StatusBadge";
import { AGENT_ORDER, agentMeta } from "../agents";

const POLL_MS = 2000;

export default function WarRoom() {
  const { invId } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const lastIdRef = useRef(0);

  useEffect(() => {
    let interval;
    let stopped = false;

    async function poll() {
      try {
        const s = await getStatus(invId);
        if (stopped) return;
        setStatus(s);

        const newEvents = await getTimeline(invId, lastIdRef.current);
        if (newEvents.length) {
          setEvents((prev) => [...prev, ...newEvents]);
          lastIdRef.current = newEvents[newEvents.length - 1].id;
        }

        const snaps = await getConfidenceEvolution(invId);
        if (!stopped) setSnapshots(snaps);

        if (s.status !== "running") {
          clearInterval(interval);
          if (s.status === "completed") {
            setTimeout(() => navigate(`/summary/${invId}`), 2200);
          }
        }
      } catch (err) {
        console.error("Poll error:", err);
      }
    }

    poll();
    interval = setInterval(poll, POLL_MS);
    return () => { stopped = true; clearInterval(interval); };
  }, [invId, navigate]);

  // Derive per-agent run state from the timeline.
  const agentState = {};
  for (const e of events) {
    if (e.event === "started") agentState[e.agent] = "running";
    else agentState[e.agent] = "done";
  }
  const runningAgent = [...events].reverse().find((e) => e.event === "started" &&
    agentState[e.agent] === "running")?.agent;

  const latestConf = snapshots.length ? snapshots[snapshots.length - 1].confidence : null;

  return (
    <>
      <header className="topbar">
        <div className="shell topbar-inner">
          <Link to="/" className="brand"><span className="spark">⚡</span> Vireon</Link>
          <span className="topbar-meta">{invId}</span>
        </div>
      </header>

      <main className="shell war">
        <div className="war-head">
          <div>
            <p className="eyebrow">War room</p>
            <h1 className="war-title">Investigation in progress</h1>
            {status && <p className="war-repo">{status.repo_path}</p>}
          </div>
          <div className="war-head-right">
            {status && <StatusBadge status={status.status} />}
            <div className="war-gauge">
              <span className="gauge-num" style={{ color: gaugeColor(latestConf) }}>
                {latestConf != null ? `${Math.round(latestConf * 100)}` : "—"}
                <span className="gauge-pct">%</span>
              </span>
              <span className="gauge-label">fused confidence</span>
            </div>
          </div>
        </div>

        <div className="war-grid">
          <section className="panel war-panel war-conf">
            <h2 className="panel-title">Confidence evolution</h2>
            <ConfidenceGraph invId={invId} snapshots={snapshots} />
          </section>

          <section className="panel war-panel war-agents">
            <h2 className="panel-title">Agents</h2>
            <div className="agent-rail">
              {AGENT_ORDER.map((a) => {
                const m = agentMeta(a);
                const st = agentState[a] ?? "pending";
                return (
                  <div
                    key={a}
                    className={`rail-agent rail-${st}`}
                    style={{ "--c": m.color }}
                  >
                    <span className="rail-glyph">{m.icon}</span>
                    <span className="rail-name">{m.label}</span>
                    <span className="rail-state">
                      {st === "running" && <span className="rail-spin" />}
                      {st === "done" && "✓"}
                    </span>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        <section className="panel war-panel war-feed">
          <h2 className="panel-title">
            Live feed
            {runningAgent && (
              <span className="feed-now" style={{ color: agentMeta(runningAgent).color }}>
                {agentMeta(runningAgent).label} working…
              </span>
            )}
          </h2>
          <Timeline events={events} />
        </section>
      </main>

      <style>{`
        .war { padding: 30px 0 80px; }
        .war-head {
          display: flex; justify-content: space-between; align-items: flex-start;
          gap: 20px; margin-bottom: 24px; flex-wrap: wrap;
        }
        .war-title {
          font-family: var(--display); font-weight: 700; font-size: 26px;
          letter-spacing: -.5px; margin: 6px 0 4px;
        }
        .war-repo { font-family: var(--mono); font-size: 13px; color: var(--text-dim); }
        .war-head-right { display: flex; align-items: center; gap: 22px; }
        .war-gauge { text-align: right; }
        .gauge-num {
          font-family: var(--display); font-weight: 700; font-size: 40px;
          line-height: 1; transition: color .4s;
        }
        .gauge-pct { font-size: 18px; opacity: .7; margin-left: 1px; }
        .gauge-label {
          display: block; font-family: var(--mono); font-size: 10px;
          letter-spacing: 1px; text-transform: uppercase; color: var(--text-faint); margin-top: 4px;
        }
        .war-grid {
          display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; margin-bottom: 16px;
        }
        .war-panel { padding: 18px 20px; }
        .panel-title {
          font-family: var(--display); font-weight: 600; font-size: 14px;
          color: var(--text); margin-bottom: 16px; display: flex;
          align-items: baseline; justify-content: space-between;
        }
        .feed-now { font-family: var(--mono); font-size: 12px; font-weight: 500; }

        .agent-rail { display: flex; flex-direction: column; gap: 7px; }
        .rail-agent {
          display: flex; align-items: center; gap: 10px;
          padding: 9px 11px; border-radius: var(--radius-sm);
          border: 1px solid var(--border); background: var(--panel-raised);
          transition: border-color .2s, opacity .2s;
        }
        .rail-pending { opacity: .45; }
        .rail-running { border-color: var(--c); box-shadow: 0 0 18px -8px var(--c); }
        .rail-done { border-color: var(--border); }
        .rail-glyph { color: var(--c); font-size: 14px; width: 16px; text-align: center; }
        .rail-name { font-family: var(--display); font-size: 13px; font-weight: 500; flex: 1; }
        .rail-state { font-family: var(--mono); font-size: 12px; color: var(--ok); }
        .rail-spin {
          display: inline-block; width: 11px; height: 11px; border-radius: 99px;
          border: 2px solid var(--c); border-top-color: transparent;
          animation: spin .7s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        @media (max-width: 880px) {
          .war-grid { grid-template-columns: 1fr; }
        }
      `}</style>
    </>
  );
}

function gaugeColor(c) {
  if (c == null) return "var(--text-faint)";
  if (c < 0.3) return "var(--bad)";
  if (c < 0.6) return "var(--warn)";
  return "var(--ok)";
}
