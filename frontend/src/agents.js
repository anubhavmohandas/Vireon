/**
 * src/agents.js — Single source of truth for agent identity.
 *
 * Every agent has one fixed color, icon, and label, used consistently across
 * the timeline, agent cards, confidence graph, and knowledge graph. Colors
 * mirror the CSS custom properties in index.css.
 */

export const AGENTS = {
  threat: { label: "Threat Intel", icon: "◎", color: "var(--agent-threat)", phase: 1 },
  static: { label: "Static Analysis", icon: "◫", color: "var(--agent-static)", phase: 1 },
  exploitability: { label: "Exploitability", icon: "◇", color: "var(--agent-exploitability)", phase: 2 },
  challenger: { label: "Challenger", icon: "⚔", color: "var(--agent-challenger)", phase: 3 },
  remediation: { label: "Remediation", icon: "⚙", color: "var(--agent-remediation)", phase: 4 },
  compliance: { label: "Compliance", icon: "▣", color: "var(--agent-compliance)", phase: 4 },
  verification: { label: "Verification", icon: "✓", color: "var(--agent-verification)", phase: 5 },
  pr: { label: "PR", icon: "↗", color: "var(--agent-pr)", phase: 5 },
};

/** Pipeline order — used to render agent cards and the workflow rail. */
export const AGENT_ORDER = [
  "threat",
  "static",
  "exploitability",
  "challenger",
  "remediation",
  "compliance",
  "verification",
  "pr",
];

export function agentMeta(name) {
  return (
    AGENTS[name] ?? { label: name, icon: "•", color: "var(--text-dim)", phase: 0 }
  );
}
