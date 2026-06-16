/**
 * pages/Landing.jsx — Landing page + scan trigger
 * Owner: Harsh
 *
 * User enters repo path → hits "Start Investigation" → POST /api/scan
 * → redirect to /war-room/:inv_id
 */

import { useState } from "react";
import { startScan } from "../services/api";

export default function Landing() {
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
      window.location.href = `/war-room/${inv_id}`;
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      {/* TODO: Harsh — build the landing UI here */}
      <h1>Vireon</h1>
      <p>Autonomous Multi-Agent Security Investigation</p>
      <form onSubmit={handleScan}>
        <input
          value={repoPath}
          onChange={(e) => setRepoPath(e.target.value)}
          placeholder="/path/to/repo"
          required
        />
        <input
          type="number"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          min={1}
          max={90}
        />
        <button type="submit" disabled={loading}>
          {loading ? "Starting..." : "Start Investigation"}
        </button>
      </form>
      {error && <p style={{ color: "red" }}>{error}</p>}
    </div>
  );
}
