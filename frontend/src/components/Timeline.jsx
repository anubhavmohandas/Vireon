/**
 * components/Timeline.jsx — Live event feed
 *
 * Props:
 *   events: Array<{ id, agent, event, detail, ts, confidence }>
 *
 * Field names match api/models.py TimelineEvent (ts / event / detail).
 * Newest events animate in at the top.
 */

import { agentMeta } from "../agents";

const EVENT_TONE = {
  started:  "var(--text-dim)",
  finished: "var(--ok)",
  approved: "var(--ok)",
  objected: "var(--warn)",
  rejected: "var(--bad)",
};

// Terminal events conclude an agent's step (vs "started").
const TERMINAL = new Set(["finished", "approved", "objected", "rejected"]);

function fmtTime(ts) {
  try {
    return new Date(ts).toLocaleTimeString([], {
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch {
    return "";
  }
}

/**
 * Pair each agent's `started` event with its next terminal event and return a
 * map of { [terminalEventId]: durationSeconds }. Agents can run more than once
 * (e.g. remediation retries), so we track the last open start per agent.
 */
function computeDurations(events) {
  const chrono = [...events].sort((a, b) => a.id - b.id);
  const openStart = {}; // agent -> ts of its last unmatched "started"
  const durations = {}; // terminal event id -> seconds
  for (const e of chrono) {
    if (e.event === "started") {
      openStart[e.agent] = e.ts;
    } else if (TERMINAL.has(e.event) && openStart[e.agent] != null) {
      const ms = new Date(e.ts) - new Date(openStart[e.agent]);
      if (!Number.isNaN(ms) && ms >= 0) durations[e.id] = ms / 1000;
      delete openStart[e.agent];
    }
  }
  return durations;
}

export default function Timeline({ events = [] }) {
  if (events.length === 0) {
    return <p className="timeline-empty">Waiting for the first agent to report in…</p>;
  }

  const durations = computeDurations(events);
  // newest first
  const ordered = [...events].sort((a, b) => b.id - a.id);

  return (
    <ol className="timeline">
      {ordered.map((e) => {
        const meta = agentMeta(e.agent);
        const tone = EVENT_TONE[e.event] ?? "var(--text-dim)";
        const dur = durations[e.id];
        return (
          <li key={e.id} className="tl-row">
            <span className="tl-rail" style={{ background: meta.color }} />
            <span className="tl-time">{fmtTime(e.ts)}</span>
            <span className="tl-glyph" style={{ color: meta.color }}>{meta.icon}</span>
            <span className="tl-agent" style={{ color: meta.color }}>{meta.label}</span>
            <span className="tl-event" style={{ color: tone }}>{e.event}</span>
            <span className="tl-detail">{e.detail}</span>
            <span className="tl-dur">{dur != null ? `+${dur.toFixed(1)}s` : ""}</span>
            {e.confidence != null ? (
              <span className="tl-conf">{Math.round(e.confidence * 100)}%</span>
            ) : (
              <span className="tl-conf tl-conf-empty">—</span>
            )}
          </li>
        );
      })}
      <style>{`
        .timeline-empty {
          font-family: var(--mono); font-size: 13px; color: var(--text-faint);
          padding: 24px 4px;
        }
        .timeline { list-style: none; display: flex; flex-direction: column; }
        .tl-row {
          position: relative;
          display: grid;
          grid-template-columns: 90px 18px 124px 78px minmax(0, 1fr) 52px 44px;
          align-items: center;
          gap: 12px;
          padding: 11px 6px 11px 16px;
          border-bottom: 1px solid var(--border);
          animation: slideIn .3s ease;
        }
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(-4px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .tl-rail {
          position: absolute; left: 0; top: 8px; bottom: 8px;
          width: 3px; border-radius: 99px;
        }
        .tl-time { font-family: var(--mono); font-size: 11px; color: var(--text-faint); white-space: nowrap; }
        .tl-glyph { font-size: 13px; text-align: center; }
        .tl-agent { font-family: var(--display); font-weight: 600; font-size: 13px; white-space: nowrap; }
        .tl-event {
          font-family: var(--mono); font-size: 10px; text-transform: uppercase;
          letter-spacing: .5px; white-space: nowrap;
        }
        .tl-detail { font-size: 13px; color: var(--text-dim); line-height: 1.4; min-width: 0; overflow-wrap: anywhere; }
        .tl-dur {
          font-family: var(--mono); font-size: 11px; color: var(--text-faint);
          white-space: nowrap; text-align: right;
        }
        .tl-conf {
          font-family: var(--mono); font-size: 12px; color: var(--text);
          font-weight: 500; white-space: nowrap; text-align: right;
        }
        .tl-conf-empty { color: var(--text-faint); font-weight: 400; }
        @media (max-width: 720px) {
          .tl-row { grid-template-columns: 18px 1fr 44px 44px; gap: 10px; }
          .tl-time, .tl-event { display: none; }
        }
      `}</style>
    </ol>
  );
}
