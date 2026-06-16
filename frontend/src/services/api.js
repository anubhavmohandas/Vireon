/**
 * src/services/api.js — Vireon API client
 * Owner: Harsh
 *
 * All backend calls go through here.
 * Change API_BASE if you're running on a different port.
 */

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ── Helpers ───────────────────────────────────────────────────────────────────

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Scan ──────────────────────────────────────────────────────────────────────

/** POST /api/scan — start a new investigation */
export async function startScan(repoPath, days = 7) {
  return request("/api/scan", {
    method: "POST",
    body: JSON.stringify({ repo_path: repoPath, days }),
  });
}

// ── Investigations ────────────────────────────────────────────────────────────

/** GET /api/investigations — list all */
export async function listInvestigations(limit = 50) {
  return request(`/api/investigations?limit=${limit}`);
}

/** GET /api/investigations/:invId/status */
export async function getStatus(invId) {
  return request(`/api/investigations/${invId}/status`);
}

// ── Timeline ──────────────────────────────────────────────────────────────────

/** GET /api/investigations/:invId/timeline?since_id=0 */
export async function getTimeline(invId, sinceId = 0) {
  return request(`/api/investigations/${invId}/timeline?since_id=${sinceId}`);
}

// ── Summary ───────────────────────────────────────────────────────────────────

/** GET /api/investigations/:invId/summary */
export async function getSummary(invId) {
  return request(`/api/investigations/${invId}/summary`);
}

// ── Graph ─────────────────────────────────────────────────────────────────────

/** GET /api/investigations/:invId/graph */
export async function getGraph(invId) {
  return request(`/api/investigations/${invId}/graph`);
}

/** GET /api/investigations/:invId/confidence */
export async function getConfidenceEvolution(invId) {
  return request(`/api/investigations/${invId}/confidence`);
}

// ── Health ────────────────────────────────────────────────────────────────────

export async function healthCheck() {
  return request("/health");
}
