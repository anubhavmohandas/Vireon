"""
db/repository.py — High-level DB operations used by the API layer.

Keeps route handlers thin — all DB logic lives here.
"""

from __future__ import annotations
from db.database import Database


class InvestigationRepo:
    """
    Facade over Database for investigation-centric queries.
    All methods return plain dicts/lists — no ORM objects leak into routes.
    """

    def __init__(self, db: Database):
        self.db = db

    # ── List / detail ─────────────────────────────────────────────────────────

    async def list_all(self, limit: int = 50) -> list[dict]:
        return await self.db.list_investigations(limit=limit)

    async def get(self, inv_id: str) -> dict | None:
        return await self.db.get_investigation(inv_id)

    async def get_or_404(self, inv_id: str) -> dict:
        inv = await self.get(inv_id)
        if inv is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"Investigation {inv_id} not found")
        return inv

    # ── Full summary ──────────────────────────────────────────────────────────

    async def get_full_summary(self, inv_id: str) -> dict:
        """
        Returns everything the UI needs for the summary page in one call.
        """
        inv = await self.get_or_404(inv_id)
        agent_results = await self.db.get_agent_results(inv_id)
        decisions = await self.db.get_decisions(inv_id)
        conf_evo = await self.db.get_confidence_evolution(inv_id)
        vulns = self._build_vulnerabilities(agent_results)

        return {
            "investigation": inv,
            "agent_results": agent_results,
            "decision_log": decisions,
            "confidence_evolution": conf_evo,
            "vulnerabilities": vulns,
        }

    def _build_vulnerabilities(self, agent_results: list[dict]) -> list[dict]:
        """
        Derive a de-duplicated Vulnerabilities list from real agent evidence.

        CVE evidence is grouped by package — one row per affected package, not
        one row per GHSA advisory (a single package can have dozens of advisories
        which floods the UI).  Static findings are listed individually since each
        points to a distinct code location.

        Status precedence (per entry):
          - challenger dismissed → "mitigated"
          - verification confirmed → "patched"
          - otherwise → "open"
        """
        by_agent = {r["agent"]: r for r in agent_results}

        patched_ok = (by_agent.get("verification") or {}).get("verdict") == "confirmed"
        dismissed_count = (by_agent.get("challenger") or {}).get("metadata", {}).get("dismissed", 0)

        vulns: list[dict] = []

        # ── CVEs from threat intel — one entry per unique package ─────────────
        threat = by_agent.get("threat")
        if threat:
            # Collect highest-severity CVE id per package
            pkg_map: dict[str, dict] = {}  # pkg → best evidence item
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
            for ev in threat.get("evidence", []):
                cve_id = ev.get("cve_id", "")
                pkg = ev.get("package", "") or "unknown"
                if not cve_id or cve_id == "?":
                    continue
                sev = (ev.get("severity") or "unknown").lower()
                existing = pkg_map.get(pkg)
                if existing is None or sev_order.get(sev, 0) > sev_order.get(
                    (existing.get("severity") or "unknown").lower(), 0
                ):
                    pkg_map[pkg] = ev

            for pkg, ev in pkg_map.items():
                cve_id = ev.get("cve_id", "")
                sev = (ev.get("severity") or "unknown").lower()
                vulns.append({
                    "id": cve_id,
                    "title": f"{cve_id} in {pkg}",
                    "severity": sev,
                    "location": pkg,
                    "status": "patched" if patched_ok else "open",
                    "confidence": threat.get("confidence", 0.5),
                    "source": ev.get("source", "OSV"),
                })

        # ── Code findings from static analysis ────────────────────────────────
        static = by_agent.get("static")
        if static:
            for i, ev in enumerate(static.get("evidence", [])):
                rule = ev.get("rule", f"FIND-{i+1:03d}")
                file_ = ev.get("file", "?")
                line = ev.get("line", "")
                msg = ev.get("message", rule)
                loc = f"{file_}:{line}" if line else file_
                vulns.append({
                    "id": rule,
                    "title": msg or rule,
                    "severity": "warning",
                    "location": loc,
                    "status": "patched" if patched_ok else "open",
                    "confidence": static.get("confidence", 0.5),
                    "source": "Semgrep",
                })

        # Challenger-dismissed findings → "mitigated" (apply to last N static entries)
        if dismissed_count and vulns:
            static_vulns = [v for v in vulns if v["source"] == "Semgrep"]
            for v in static_vulns[-dismissed_count:]:
                v["status"] = "mitigated"

        return vulns

    # ── Timeline ──────────────────────────────────────────────────────────────

    async def get_timeline(
        self, inv_id: str, since_id: int = 0
    ) -> list[dict]:
        """
        Returns timeline events. `since_id` enables incremental polling —
        frontend passes the last seen event ID, gets only new events.
        """
        events = await self.db.get_timeline(inv_id)
        return [e for e in events if e["id"] > since_id]

    # ── Graph ─────────────────────────────────────────────────────────────────

    async def get_graph_data(self, inv_id: str) -> dict:
        """
        Returns networkx graph as {nodes, edges} JSON for the UI.
        Graph is stored in SharedState (not DB) so we reconstruct from agent results.
        Falls back to CVE+package data from agent_results if graph not serialized.
        """
        results = await self.db.get_agent_results(inv_id)
        threat = next((r for r in results if r["agent"] == "threat"), None)
        static = next((r for r in results if r["agent"] == "static"), None)

        nodes = []
        edges = []

        # Build graph from threat intel evidence
        if threat:
            meta = threat.get("metadata", {})
            for ev in threat.get("evidence", []):
                cve_id = ev.get("cve_id", "")
                pkg = ev.get("package", "")
                sev = ev.get("severity", "UNKNOWN")
                if cve_id:
                    nodes.append({"id": f"cve:{cve_id}", "type": "cve", "label": cve_id, "severity": sev})
                if pkg:
                    nodes.append({"id": f"pkg:{pkg}", "type": "package", "label": pkg})
                if cve_id and pkg:
                    edges.append({"source": f"pkg:{pkg}", "target": f"cve:{cve_id}", "label": "vulnerable_to"})

        # Deduplicate nodes by id
        seen = set()
        unique_nodes = []
        for n in nodes:
            if n["id"] not in seen:
                seen.add(n["id"])
                unique_nodes.append(n)

        return {"nodes": unique_nodes, "edges": edges}
