/**
 * src/services/api.js — Vireon API client
 *
 * All backend calls go through here. The endpoint contract matches
 * api/routes/*.py and api/models.py exactly.
 *
 * Routes are live — mock is now opt-in, not opt-out.
 * Set VITE_USE_MOCK=1 to force mock mode (demo without a running backend).
 * The mock also kicks in automatically on 501/404/network errors as a last
 * resort so the UI never fully dead-ends.
 */

import * as mock from "./mock";

const API_BASE = import.meta.env.VITE_API_URL || ""; // "" -> same-origin via Vite proxy

// Live API by default. Set VITE_USE_MOCK=1 to use mock data (demo mode).
const USE_MOCK = import.meta.env.VITE_USE_MOCK === "1";

class Recoverable extends Error {}

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
  } catch {
    // network error / server down
    throw new Recoverable("network");
  }
  if (res.status === 501 || res.status === 404) throw new Recoverable(`http ${res.status}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Try the live endpoint; fall back to mock when mock mode is on or the live
 * call fails in a recoverable way (501/404/network). Other errors propagate.
 */
async function withFallback(liveFn, mockFn) {
  if (USE_MOCK) return mockFn();
  try {
    return await liveFn();
  } catch (err) {
    if (err instanceof Recoverable) return mockFn();
    throw err;
  }
}

// -- Scan ---------------------------------------------------------------------

/** POST /api/scan -- start a new investigation. Returns { inv_id, status, message }. */
export function startScan(repoPath, days = 7) {
  return withFallback(
    () =>
      request("/api/scan", {
        method: "POST",
        body: JSON.stringify({ repo_path: repoPath, days }),
      }),
    () => mock.startScan(repoPath, days)
  );
}

// -- Investigations -----------------------------------------------------------

/** GET /api/investigations -- list all. */
export function listInvestigations(limit = 50) {
  return withFallback(
    () => request(`/api/investigations?limit=${limit}`),
    () => mock.listInvestigations(limit)
  );
}

/** GET /api/investigations/:invId/status */
export function getStatus(invId) {
  return withFallback(
    () => request(`/api/investigations/${invId}/status`),
    () => mock.getStatus(invId)
  );
}

// -- Timeline -----------------------------------------------------------------

/** GET /api/investigations/:invId/timeline?since_id=0 */
export function getTimeline(invId, sinceId = 0) {
  return withFallback(
    () => request(`/api/investigations/${invId}/timeline?since_id=${sinceId}`),
    () => mock.getTimeline(invId, sinceId)
  );
}

// -- Summary ------------------------------------------------------------------

/** GET /api/investigations/:invId/summary */
export function getSummary(invId) {
  return withFallback(
    () => request(`/api/investigations/${invId}/summary`),
    () => mock.getSummary(invId)
  );
}

// -- Graph --------------------------------------------------------------------

/** GET /api/investigations/:invId/graph -> { nodes, edges } */
export function getGraph(invId) {
  return withFallback(
    () => request(`/api/investigations/${invId}/graph`),
    () => mock.getGraph(invId)
  );
}

/** GET /api/investigations/:invId/confidence -> ConfidenceSnapshot[] */
export function getConfidenceEvolution(invId) {
  return withFallback(
    () => request(`/api/investigations/${invId}/confidence`),
    () => mock.getConfidenceEvolution(invId)
  );
}

// -- Health -------------------------------------------------------------------

export function healthCheck() {
  return request("/health");
}
