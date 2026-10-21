/**
 * components/Vulnerabilities.jsx — The findings view.
 *
 * The security payoff of the whole pipeline: every CVE / static finding, its
 * severity, where it lives, what the agents decided (patched / mitigated /
 * dismissed / confirmed), and the fix. Reads `summary.vulnerabilities`.
 *
 * Props:
 *   items: Array<{
 *     id, title, severity, location, reachable_via?, status,
 *     confidence, fix?, source?
 *   }>
 */

const SEVERITY = {
  high:    { label: "High",    color: "var(--bad)" },
  medium:  { label: "Medium",  color: "var(--warn)" },
  warning: { label: "Warning", color: "var(--agent-remediation)" },
  low:     { label: "Low",     color: "var(--text-dim)" },
};

const STATUS = {
  patched:   { label: "Patched",   color: "var(--ok)" },
  mitigated: { label: "Mitigated", color: "var(--warn)" },
  dismissed: { label: "Dismissed", color: "var(--text-dim)" },
  confirmed: { label: "Confirmed", color: "var(--violet)" },
};

const SEV_ORDER = { high: 0, medium: 1, warning: 2, low: 3 };

export default function Vulnerabilities({ items = [] }) {
  if (!items.length) {
    return <p className="vuln-empty">No vulnerabilities were surfaced in this run.</p>;
  }

  const sorted = [...items].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  );

  // Counts by severity for the header summary.
  const counts = sorted.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="vuln">
      <div className="vuln-summary">
        {["high", "medium", "warning", "low"].map((sev) =>
          counts[sev] ? (
            <span key={sev} className="vuln-count">
              <span className="vuln-dot" style={{ background: SEVERITY[sev].color }} />
              {counts[sev]} {SEVERITY[sev].label.toLowerCase()}
            </span>
          ) : null
        )}
      </div>

      <ul className="vuln-list">
        {sorted.map((v) => {
          const sev = SEVERITY[v.severity] ?? SEVERITY.low;
          const st = STATUS[v.status] ?? STATUS.confirmed;
          return (
            <li key={v.id} className="vuln-row" style={{ borderLeftColor: sev.color }}>
              <div className="vuln-main">
                <div className="vuln-titleline">
                  <span className="vuln-sev" style={{ color: sev.color, borderColor: sev.color }}>
                    {sev.label}
                  </span>
                  <span className="vuln-title">{v.title}</span>
                  <span className="vuln-id">{v.id}</span>
                </div>
                <div className="vuln-meta">
                  <span className="vuln-loc">{v.location}</span>
                  {v.reachable_via && (
                    <span className="vuln-reach">reachable via {v.reachable_via}</span>
                  )}
                  {v.source && <span className="vuln-src">{v.source}</span>}
                </div>
                {v.fix && (
                  <p className="vuln-fix">
                    <span className="vuln-fix-label">Fix</span> {v.fix}
                  </p>
                )}
              </div>
              <div className="vuln-side">
                <span className="vuln-status" style={{ color: st.color, borderColor: st.color }}>
                  {st.label}
                </span>
                {v.confidence != null && (
                  <span className="vuln-conf">{Math.round(v.confidence * 100)}%</span>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      <style>{`
        .vuln-empty { font-family: var(--mono); font-size: 13px; color: var(--text-faint); padding: 8px 0; }
        .vuln-summary { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 14px; }
        .vuln-count {
          display: inline-flex; align-items: center; gap: 7px;
          font-family: var(--mono); font-size: 12px; color: var(--text-dim);
        }
        .vuln-dot { width: 8px; height: 8px; border-radius: 99px; }
        .vuln-list { list-style: none; display: flex; flex-direction: column; gap: 10px; }
        .vuln-row {
          display: flex; gap: 16px; align-items: flex-start;
          background: var(--panel); border: 1px solid var(--border);
          border-left: 3px solid var(--text-dim);
          border-radius: 0 var(--radius) var(--radius) 0;
          padding: 13px 16px;
        }
        .vuln-main { flex: 1; min-width: 0; }
        .vuln-titleline { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
        .vuln-sev {
          font-family: var(--mono); font-size: 10px; font-weight: 500;
          letter-spacing: .5px; text-transform: uppercase;
          padding: 2px 7px; border: 1px solid; border-radius: 5px;
        }
        .vuln-title {
          font-family: var(--display); font-weight: 600; font-size: 14px;
          color: var(--text); overflow-wrap: anywhere;
        }
        .vuln-id { font-family: var(--mono); font-size: 11px; color: var(--text-faint); }
        .vuln-meta {
          display: flex; flex-wrap: wrap; gap: 14px; margin-top: 7px;
          font-family: var(--mono); font-size: 11px; color: var(--text-dim);
        }
        .vuln-loc { color: var(--text-dim); }
        .vuln-reach { color: var(--text-faint); }
        .vuln-src { color: var(--text-faint); margin-left: auto; }
        .vuln-fix {
          margin-top: 10px; font-size: 12.5px; line-height: 1.5; color: var(--text-dim);
          border-top: 1px solid var(--border); padding-top: 9px; overflow-wrap: anywhere;
        }
        .vuln-fix-label {
          font-family: var(--mono); font-size: 10px; text-transform: uppercase;
          letter-spacing: .5px; color: var(--ok); margin-right: 6px;
        }
        .vuln-side {
          display: flex; flex-direction: column; align-items: flex-end; gap: 8px;
          flex-shrink: 0;
        }
        .vuln-status {
          font-family: var(--mono); font-size: 11px; font-weight: 500;
          padding: 3px 9px; border: 1px solid; border-radius: 5px; white-space: nowrap;
        }
        .vuln-conf { font-family: var(--mono); font-size: 13px; color: var(--text); }
        @media (max-width: 620px) {
          .vuln-src { margin-left: 0; }
        }
      `}</style>
    </div>
  );
}
