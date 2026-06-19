/**
 * src/services/mock.js — Demo data that mirrors the real API model shapes
 * (api/models.py). Used as a fallback while the FastAPI routes still return 501.
 *
 * The mock simulates a *live* run: timeline events and confidence snapshots are
 * revealed over wall-clock time after a scan "starts", so the War Room animates
 * exactly as it will against the real backend. Scenario follows the canonical
 * Vireon demo: Challenger objects (confidence dips), Compliance rejects once,
 * Remediation retries, then Verification passes.
 */

const REPO = "/Users/anubhav/Documents/SAGE";
const SCENARIO_MS = 22000; // full run takes ~22s in the demo

// One run is held in memory keyed by inv_id.
const runs = new Map();

function nowIso(offsetMs = 0) {
  return new Date(Date.now() + offsetMs).toISOString();
}

/** The scripted timeline. Each event's `at` is ms after scan start. */
function buildScript(invId, startMs) {
  const ev = (id, at, agent, event, detail, confidence = null) => ({
    id,
    inv_id: invId,
    ts: new Date(startMs + at).toISOString(),
    agent,
    event,
    detail,
    confidence,
    at,
  });

  return [
    ev(1, 800, "threat", "started", "Fetching CVEs from OSV.dev + NVD"),
    ev(2, 3200, "threat", "finished", "82 CVEs fetched · 3 relevant to stack", 0.79),
    ev(3, 3600, "static", "started", "Semgrep scan: python, js, xss, secrets, owasp"),
    ev(4, 6400, "static", "finished", "3 findings (1 high, 2 warning)", 0.9),
    ev(5, 6900, "exploitability", "started", "LLM triage — grouping by file, reading source"),
    ev(6, 10200, "exploitability", "finished", "3 confirmed exploitable · 0 dismissed", 0.9),
    ev(7, 10700, "challenger", "started", "Red team review — hunting for mitigations"),
    ev(8, 13600, "challenger", "objected", "Found ORM guard on 1 finding — confidence pressured", 0.42),
    ev(9, 13900, "challenger", "finished", "Net: 2 findings hold, fused confidence holds above abort line", 0.66),
    ev(10, 14400, "remediation", "started", "Generating patch + dependency bumps"),
    ev(11, 16200, "remediation", "finished", "Patch generated for design-canvas.jsx", 0.8),
    ev(12, 16700, "compliance", "started", "Security policy gate review"),
    ev(13, 17600, "compliance", "rejected", "Patch weakened an auth check — forcing retry", 0.3),
    ev(14, 17900, "remediation", "started", "Retry #2 — preserving auth path"),
    ev(15, 19200, "remediation", "finished", "Revised patch generated", 0.82),
    ev(16, 19500, "compliance", "approved", "Policy satisfied — patch approved", 0.85),
    ev(17, 19900, "verification", "started", "Apply patch in tmpdir · run tests · re-run Semgrep"),
    ev(18, 21400, "verification", "finished", "Tests pass · Semgrep re-scan clean", 0.92),
    ev(19, 21700, "pr", "started", "Opening GitHub PR"),
    ev(20, 22000, "pr", "finished", "No token — full draft saved to output/pr_draft.md", 0.95),
  ];
}

function getRun(invId) {
  let run = runs.get(invId);
  if (!run) {
    // If someone deep-links a War Room without starting a scan, synthesize one
    // that started "now" so the demo still animates.
    const startMs = Date.now();
    run = { invId, startMs, script: buildScript(invId, startMs) };
    runs.set(invId, run);
  }
  return run;
}

function elapsed(run) {
  return Date.now() - run.startMs;
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Scan ──────────────────────────────────────────────────────────────────────

export async function startScan(repoPath /* , days */) {
  await delay(450);
  const invId = `INV-2026-${String(Math.floor(10000 + Math.random() * 89999))}`;
  const startMs = Date.now();
  runs.set(invId, {
    invId,
    repoPath: repoPath || REPO,
    startMs,
    script: buildScript(invId, startMs),
  });
  return {
    inv_id: invId,
    status: "running",
    message: "Investigation started",
  };
}

// ── Status ──────────────────────────────────────────────────────────────────

export async function getStatus(invId) {
  await delay(120);
  const run = getRun(invId);
  const t = elapsed(run);
  const done = t >= SCENARIO_MS;
  const fused = done ? 0.95 : null;
  return {
    inv_id: invId,
    repo_path: run.repoPath || REPO,
    status: done ? "completed" : "running",
    started_at: new Date(run.startMs).toISOString(),
    completed_at: done ? new Date(run.startMs + SCENARIO_MS).toISOString() : null,
    fused_confidence: fused,
    error: null,
  };
}

// ── Timeline (incremental) ────────────────────────────────────────────────────

export async function getTimeline(invId, sinceId = 0) {
  await delay(120);
  const run = getRun(invId);
  const t = elapsed(run);
  return run.script
    .filter((e) => e.at <= t && e.id > sinceId)
    .map(({ at, ...e }) => e); // strip internal `at`
}

// ── Confidence evolution ──────────────────────────────────────────────────────

export async function getConfidenceEvolution(invId) {
  await delay(120);
  const run = getRun(invId);
  const t = elapsed(run);
  let id = 0;
  return run.script
    .filter((e) => e.confidence != null && e.at <= t)
    .map((e) => ({
      id: ++id,
      inv_id: invId,
      ts: e.ts,
      agent: e.agent,
      confidence: e.confidence,
      label: e.event,
    }));
}

// ── Graph ─────────────────────────────────────────────────────────────────────

export async function getGraph(invId) {
  await delay(150);
  return {
    nodes: [
      { id: "repo", type: "repo", label: "SAGE", severity: null },
      { id: "react", type: "package", label: "react@18.2.0", severity: null },
      { id: "axios", type: "package", label: "axios@0.21.1", severity: "high" },
      { id: "lodash", type: "package", label: "lodash@4.17.19", severity: "medium" },
      { id: "design-canvas.jsx", type: "file", label: "design-canvas.jsx", severity: null },
      { id: "executor.py", type: "file", label: "executor.py", severity: null },
      { id: "CVE-2021-3749", type: "cve", label: "CVE-2021-3749 · axios SSRF", severity: "high" },
      { id: "CVE-2020-8203", type: "cve", label: "CVE-2020-8203 · lodash proto", severity: "medium" },
      { id: "POSTMSG-285", type: "cve", label: "Wildcard postMessage", severity: "warning" },
    ],
    edges: [
      { source: "repo", target: "react", label: "depends_on" },
      { source: "repo", target: "axios", label: "depends_on" },
      { source: "repo", target: "lodash", label: "depends_on" },
      { source: "repo", target: "design-canvas.jsx", label: "contains" },
      { source: "repo", target: "executor.py", label: "contains" },
      { source: "axios", target: "CVE-2021-3749", label: "has_cve" },
      { source: "lodash", target: "CVE-2020-8203", label: "has_cve" },
      { source: "design-canvas.jsx", target: "react", label: "imports" },
      { source: "design-canvas.jsx", target: "POSTMSG-285", label: "has_finding" },
      { source: "executor.py", target: "axios", label: "imports" },
    ],
  };
}

// ── Full summary ──────────────────────────────────────────────────────────────

export async function getSummary(invId) {
  await delay(180);
  const run = getRun(invId);
  const created = new Date(run.startMs + SCENARIO_MS).toISOString();

  const agentResult = (agent, verdict, confidence, duration_ms, evidence, metadata = {}) => ({
    inv_id: invId,
    agent,
    verdict,
    confidence,
    evidence,
    metadata,
    duration_ms,
    created_at: created,
  });

  const status = {
    inv_id: invId,
    repo_path: run.repoPath || REPO,
    status: "completed",
    started_at: new Date(run.startMs).toISOString(),
    completed_at: created,
    fused_confidence: 0.95,
    error: null,
  };

  return {
    investigation: status,
    agent_results: [
      agentResult("threat", "confirmed", 0.79, 2400, [
        { kind: "cve", detail: "82 CVEs fetched, 3 relevant to detected stack" },
      ]),
      agentResult("static", "confirmed", 0.9, 2800, [
        { kind: "finding", detail: "Wildcard postMessage in design-canvas.jsx:285" },
        { kind: "finding", detail: "axios SSRF reachable via executor.py" },
      ]),
      agentResult("exploitability", "confirmed", 0.9, 3300, [
        { kind: "analysis", detail: "3 findings confirmed exploitable, 0 dismissed" },
      ]),
      agentResult("challenger", "counter_evidence_found", 0.42, 2900, [
        { kind: "mitigation", detail: "ORM guard found on 1 finding — reduced confidence" },
      ], { dismissed: 1 }),
      agentResult("remediation", "confirmed", 0.82, 3300, [
        { kind: "patch", detail: "Patch for design-canvas.jsx + axios bump to 1.6.0" },
      ], { attempts: 2 }),
      agentResult("compliance", "confirmed", 0.85, 1800, [
        { kind: "policy", detail: "Approved on retry #2 — auth path preserved" },
      ], { status: "APPROVED", rejections: 1 }),
      agentResult("verification", "confirmed", 0.92, 1500, [
        { kind: "test", detail: "Tests pass, post-patch Semgrep re-scan clean" },
      ]),
      agentResult("pr", "confirmed", 0.95, 400, [
        { kind: "pr", detail: "Draft saved to output/pr_draft.md (no GITHUB_TOKEN)" },
      ], { pr_path: "output/pr_draft.md" }),
    ],
    decision_log: [
      { id: 1, inv_id: invId, ts: nowIso(-12000), agent: "challenger", action: "objection", reason: "ORM parameterization mitigates 1 SQLi finding", metadata: {} },
      { id: 2, inv_id: invId, ts: nowIso(-9000), agent: "compliance", action: "reject", reason: "First patch weakened an auth check", metadata: { attempt: 1 } },
      { id: 3, inv_id: invId, ts: nowIso(-6000), agent: "compliance", action: "approve", reason: "Revised patch preserves auth path", metadata: { attempt: 2 } },
      { id: 4, inv_id: invId, ts: nowIso(-2000), agent: "pr", action: "draft_saved", reason: "No GitHub token configured", metadata: { path: "output/pr_draft.md" } },
    ],
    vulnerabilities: [
      {
        id: "CVE-2021-3749",
        title: "axios SSRF via follow-redirects",
        severity: "high",
        location: "axios@0.21.1",
        reachable_via: "executor.py",
        status: "patched",
        confidence: 0.9,
        fix: "Bump axios to 1.6.0 — drops the vulnerable redirect handling.",
        source: "OSV.dev",
      },
      {
        id: "FIND-001",
        title: "Wildcard target origin in postMessage",
        severity: "warning",
        location: "design-canvas.jsx:285",
        status: "patched",
        confidence: 0.82,
        fix: "Pin the target origin and validate event.origin on receipt.",
        source: "Semgrep",
      },
      {
        id: "CVE-2020-8203",
        title: "lodash prototype pollution",
        severity: "medium",
        location: "lodash@4.17.19",
        status: "patched",
        confidence: 0.88,
        fix: "Bump lodash to 4.17.21.",
        source: "OSV.dev",
      },
      {
        id: "FIND-002",
        title: "Possible SQL injection in query builder",
        severity: "high",
        location: "db/query.py:96",
        status: "mitigated",
        confidence: 0.42,
        fix: "No change needed — the ORM already parameterizes this input (Challenger).",
        source: "Semgrep",
      },
    ],
    confidence_evolution: await getConfidenceEvolution(invId),
  };
}

// ── List ──────────────────────────────────────────────────────────────────────

export async function listInvestigations(limit = 50) {
  await delay(120);
  return Array.from(runs.values())
    .slice(0, limit)
    .map((run) => ({
      inv_id: run.invId,
      repo_path: run.repoPath || REPO,
      status: elapsed(run) >= SCENARIO_MS ? "completed" : "running",
      started_at: new Date(run.startMs).toISOString(),
      completed_at: null,
      fused_confidence: null,
      error: null,
    }));
}
