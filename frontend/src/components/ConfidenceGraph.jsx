/**
 * components/ConfidenceGraph.jsx — Confidence evolution chart
 *
 * The signature view: fused confidence rising and falling as agents report.
 * The Challenger's dip is a real downward break; the 0.30 abort threshold is
 * drawn as a reference line so judges can see how close a finding came to
 * being dropped.
 *
 * Props:
 *   invId: string
 *   snapshots?: ConfidenceSnapshot[]   — pass directly, or omit to fetch
 */

import { useEffect, useState } from "react";
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis,
  ReferenceLine, Tooltip, CartesianGrid, Dot,
} from "recharts";
import { getConfidenceEvolution } from "../services/api";
import { agentMeta } from "../agents";

export default function ConfidenceGraph({ invId, snapshots: propSnapshots }) {
  const [snapshots, setSnapshots] = useState(propSnapshots ?? []);

  useEffect(() => {
    if (propSnapshots) { setSnapshots(propSnapshots); return; }
    getConfidenceEvolution(invId).then(setSnapshots).catch(console.error);
  }, [invId, propSnapshots]);

  if (!snapshots.length) {
    return <p className="cg-empty">No confidence data yet…</p>;
  }

  const data = snapshots.map((s, i) => ({
    i,
    agent: s.agent,
    label: agentMeta(s.agent).label,
    conf: s.confidence,
  }));

  const AgentDot = (props) => {
    const { cx, cy, payload } = props;
    if (cx == null || cy == null) return null;
    return <Dot cx={cx} cy={cy} r={4.5} fill={agentMeta(payload.agent).color} stroke="var(--bg)" strokeWidth={1.5} />;
  };

  const CustomTip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    const p = payload[0].payload;
    return (
      <div className="cg-tip">
        <span className="cg-tip-agent" style={{ color: agentMeta(p.agent).color }}>
          {p.label}
        </span>
        <span className="cg-tip-conf">{Math.round(p.conf * 100)}% confidence</span>
      </div>
    );
  };

  return (
    <div className="cg-wrap">
      <ResponsiveContainer width="100%" height={220}>
        <LineChart data={data} margin={{ top: 8, right: 16, bottom: 4, left: -18 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="i" type="number" domain={[0, Math.max(data.length - 1, 1)]}
            ticks={data.map((d) => d.i)}
            tickFormatter={(i) => data[i]?.label ?? ""}
            tick={{ fill: "var(--text-faint)", fontSize: 10, fontFamily: "var(--mono)" }}
            axisLine={{ stroke: "var(--border)" }} tickLine={false} interval={0} angle={-18}
            textAnchor="end" height={48}
          />
          <YAxis
            domain={[0, 1]} ticks={[0, 0.3, 0.6, 1]}
            tickFormatter={(v) => `${Math.round(v * 100)}`}
            tick={{ fill: "var(--text-faint)", fontSize: 10, fontFamily: "var(--mono)" }}
            axisLine={false} tickLine={false}
          />
          <ReferenceLine
            y={0.3} stroke="var(--bad)" strokeDasharray="4 4"
            label={{ value: "abort", fill: "var(--bad)", fontSize: 10, position: "insideTopRight", fontFamily: "var(--mono)" }}
          />
          <Tooltip content={<CustomTip />} cursor={{ stroke: "var(--border-bright)" }} />
          <Line
            type="monotone" dataKey="conf" stroke="var(--violet)" strokeWidth={2}
            dot={<AgentDot />} activeDot={{ r: 6 }} isAnimationActive
          />
        </LineChart>
      </ResponsiveContainer>
      <style>{`
        .cg-empty { font-family: var(--mono); font-size: 13px; color: var(--text-faint); padding: 16px 4px; }
        .cg-wrap { width: 100%; }
        .cg-tip {
          background: var(--panel-raised); border: 1px solid var(--border-bright);
          border-radius: 8px; padding: 8px 11px; display: flex; flex-direction: column; gap: 2px;
        }
        .cg-tip-agent { font-family: var(--display); font-weight: 600; font-size: 13px; }
        .cg-tip-conf { font-family: var(--mono); font-size: 11px; color: var(--text-dim); }
      `}</style>
    </div>
  );
}
